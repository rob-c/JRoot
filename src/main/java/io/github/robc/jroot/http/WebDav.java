package io.github.robc.jroot.http;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdException;
import io.github.robc.jroot.XrdServerException;
import io.github.robc.jroot.wire.Types.DirEntry;
import io.github.robc.jroot.wire.Types.StatInfo;
import io.github.robc.jroot.wire.XrdConst;

/**
 * WebDAV on top of the HTTP transport.
 *
 * <p>Only the part of RFC 4918 that storage actually uses is here: PROPFIND
 * for stat and listing, MKCOL, MOVE, COPY, and DELETE. Locking, property
 * writes and versioning are deliberately absent — no WLCG endpoint asks for
 * them, and implementing them unused would be dead weight.
 *
 * <p>The multistatus parser refuses a document type declaration outright,
 * which closes the entity-expansion and external-entity holes that come free
 * with a default {@link DocumentBuilderFactory}: a listing is parsed from
 * whatever a redirect landed on, so it is not trusted input.
 */
public final class WebDav extends HttpStorage {

    /** The properties worth asking for; a bare {@code allprop} makes some
     *  servers compute checksums for every entry of a large directory. */
    private static final byte[] PROPFIND_BODY = ("""
            <?xml version="1.0" encoding="utf-8"?>
            <D:propfind xmlns:D="DAV:">
              <D:prop>
                <D:resourcetype/>
                <D:getcontentlength/>
                <D:getlastmodified/>
                <D:getetag/>
              </D:prop>
            </D:propfind>
            """).getBytes(StandardCharsets.UTF_8);

    private static final String DAV = "DAV:";

    public WebDav(Config config) {
        super(config);
    }

    // -----------------------------------------------------------------
    // Operations
    // -----------------------------------------------------------------

    /**
     * PROPFIND with {@code Depth: 0}. Preferred over {@code HEAD} because it
     * says whether the target is a collection instead of leaving it to be
     * guessed from a trailing slash.
     */
    @Override
    public StatInfo stat(String url) {
        URI uri = normalise(url);
        List<Entry> entries = propfind(uri, 0);
        String wanted = trimSlash(uri.getPath());
        for (Entry entry : entries) {
            if (trimSlash(entry.path()).equals(wanted)) {
                return entry.stat();
            }
        }
        if (entries.size() == 1) {
            return entries.get(0).stat();       // a server that rewrote the href
        }
        throw new XrdServerException(XrdConst.kXR_NotFound,
                "PROPFIND " + uri + " returned no entry for it");
    }

    /** PROPFIND with {@code Depth: 1}: the children, without the collection itself. */
    public List<DirEntry> list(String url) {
        URI uri = normalise(url);
        String parent = trimSlash(uri.getPath());
        List<DirEntry> out = new ArrayList<>();
        for (Entry entry : propfind(uri, 1)) {
            String path = trimSlash(entry.path());
            if (path.equals(parent)) {
                continue;                       // the collection is its own first child
            }
            out.add(new DirEntry(nameOf(path), parent, Optional.of(entry.stat())));
        }
        return out;
    }

    /** MKCOL. {@code makePath} creates missing parents, as {@code mkdir -p} does. */
    public void mkdir(String url, boolean makePath) {
        URI uri = normalise(url);
        if (makePath) {
            for (String ancestor : ancestors(uri)) {
                mkcol(uri.resolve(ancestor), true);
            }
        }
        mkcol(uri, false);
    }

    public void mkdir(String url) {
        mkdir(url, false);
    }

    private void mkcol(URI uri, boolean tolerateExisting) {
        HttpResponse<Void> response = send(builder(uri)
                .method("MKCOL", BodyPublishers.noBody()),
                BodyHandlers.discarding(), uri);
        int status = response.statusCode();
        if (status >= 200 && status < 300) {
            return;
        }
        // 405 on MKCOL means "already a collection", which is only an error
        // when the caller asked for this exact directory to be new.
        if (status == 405 || status == 301) {
            if (tolerateExisting) {
                return;
            }
            throw new XrdServerException(XrdConst.kXR_ItExists, "MKCOL " + uri + " exists");
        }
        check(response, uri, "MKCOL");
    }

    /** MOVE, which is both rename and relocation in WebDAV. */
    public void move(String source, String target, boolean overwrite) {
        transfer("MOVE", source, target, overwrite);
    }

    public void move(String source, String target) {
        move(source, target, true);
    }

    /** COPY. Third-party copy (a {@code Source} on a remote host) is not this
     *  method — that is a server-to-server transfer and belongs to the caller. */
    public void copy(String source, String target, boolean overwrite) {
        transfer("COPY", source, target, overwrite);
    }

    private void transfer(String method, String source, String target, boolean overwrite) {
        URI from = normalise(source);
        URI to = normalise(target);
        HttpResponse<Void> response = send(builder(from)
                .method(method, BodyPublishers.noBody())
                .header("Destination", to.toString())
                .header("Overwrite", overwrite ? "T" : "F"),
                BodyHandlers.discarding(), from);
        if (response.statusCode() == 412) {
            throw new XrdServerException(XrdConst.kXR_ItExists,
                    method + " " + from + " to " + to + ": destination exists");
        }
        check(response, from, method);
    }

    /**
     * A third-party copy: the two servers move the data between themselves
     * and this client only starts it and watches.
     *
     * <p>The request goes to whichever end is asked to do the work — a
     * {@code Destination} header pushes, a {@code Source} header pulls — and
     * the credential for the *other* end travels in
     * {@code TransferHeaderAuthorization}, which the active server replays as
     * that end's {@code Authorization}. The reply is a chunked stream of
     * progress markers ending in {@code success:} or {@code failure:}, so a
     * 200 alone does not mean the transfer worked.
     *
     * @param pull true to ask the destination to fetch, false to ask the
     *             source to send; pull is what WLCG deployments use, because
     *             the destination is the end that knows it has space
     * @param remoteToken the bearer token for the far end, or null to reuse
     *                    this client's own
     */
    public void thirdPartyCopy(String source, String target, boolean pull,
                               String remoteToken, boolean overwrite) {
        URI active = normalise(pull ? target : source);
        URI passive = normalise(pull ? source : target);
        String credential = remoteToken != null ? remoteToken : tokenOrNull();
        var builder = builder(active)
                .method("COPY", BodyPublishers.noBody())
                .header(pull ? "Source" : "Destination", passive.toString())
                .header("Overwrite", overwrite ? "T" : "F")
                .header("X-No-Delegate", "true")
                .header("Credential", "none");
        if (credential != null) {
            builder.header("TransferHeaderAuthorization", "Bearer " + credential);
        }
        HttpResponse<byte[]> response =
                send(builder, BodyHandlers.ofByteArray(), active);
        check(response, active, "COPY");
        String outcome = finalLine(new String(response.body(), StandardCharsets.UTF_8));
        if (outcome == null) {
            throw new XrdException("COPY " + active
                    + " ended without saying whether it succeeded");
        }
        if (!outcome.regionMatches(true, 0, "success", 0, 7)) {
            throw new XrdServerException(XrdConst.kXR_ServerError,
                    "third-party copy of " + source + " to " + target + ": " + outcome);
        }
    }

    public void thirdPartyCopy(String source, String target) {
        thirdPartyCopy(source, target, true, null, true);
    }

    /** The last non-blank line of a performance-marker stream, which is the
     *  one that says how the transfer ended. */
    private static String finalLine(String body) {
        String[] lines = body.split("\r?\n");
        for (int i = lines.length - 1; i >= 0; i--) {
            String line = lines[i].trim();
            if (!line.isEmpty()) {
                return line;
            }
        }
        return null;
    }

    /** DELETE of a collection, which WebDAV makes recursive by definition. */
    public void rmdir(String url) {
        delete(url);
    }

    // -----------------------------------------------------------------
    // PROPFIND
    // -----------------------------------------------------------------

    /** One {@code <D:response>} that carried a successful propstat. */
    private record Entry(String path, StatInfo stat) {}

    private List<Entry> propfind(URI uri, int depth) {
        HttpResponse<byte[]> response = send(builder(uri)
                .method("PROPFIND", BodyPublishers.ofByteArray(PROPFIND_BODY))
                .header("Depth", Integer.toString(depth))
                .header("Content-Type", "application/xml; charset=utf-8"),
                BodyHandlers.ofByteArray(), uri, BodyPublishers.ofByteArray(PROPFIND_BODY));
        check(response, uri, "PROPFIND");
        if (response.statusCode() != 207) {
            throw new XrdException("PROPFIND " + uri + " answered "
                    + response.statusCode() + " instead of 207 Multi-Status");
        }
        return parseMultistatus(response.body(), uri);
    }

    static List<Entry> parseMultistatus(byte[] body, URI uri) {
        Document document = parseXml(body, uri);
        NodeList responses = document.getElementsByTagNameNS(DAV, "response");
        List<Entry> out = new ArrayList<>();
        for (int i = 0; i < responses.getLength(); i++) {
            Element response = (Element) responses.item(i);
            String href = text(child(response, "href"));
            if (href == null) {
                continue;
            }
            Element prop = successfulProp(response);
            if (prop == null) {
                continue;                       // 404 or 403 on this entry alone
            }
            String path = pathOf(href, uri);
            out.add(new Entry(path, statOf(prop, path)));
        }
        return out;
    }

    /** The {@code <D:prop>} of the propstat whose status was 2xx. */
    private static Element successfulProp(Element response) {
        NodeList propstats = response.getElementsByTagNameNS(DAV, "propstat");
        for (int i = 0; i < propstats.getLength(); i++) {
            Element propstat = (Element) propstats.item(i);
            String status = text(child(propstat, "status"));
            if (status != null && statusCode(status) / 100 != 2) {
                continue;
            }
            Element prop = child(propstat, "prop");
            if (prop != null) {
                return prop;
            }
        }
        return null;
    }

    private static StatInfo statOf(Element prop, String path) {
        Element resourcetype = child(prop, "resourcetype");
        boolean directory = resourcetype != null
                && child(resourcetype, "collection") != null;
        long size = parseLong(text(child(prop, "getcontentlength")));
        long mtime = 0;
        String modified = text(child(prop, "getlastmodified"));
        if (modified != null) {
            mtime = parseHttpDate(modified);
        }
        String etag = text(child(prop, "getetag"));
        int flags = XrdConst.kXR_readable | (directory ? XrdConst.kXR_isDir : 0);
        return new StatInfo(etag == null ? "" : etag.replace("\"", ""),
                directory ? 0 : size, flags, mtime, path);
    }

    /** {@code "HTTP/1.1 200 OK"} → 200; anything unreadable counts as failed. */
    private static int statusCode(String status) {
        String[] parts = status.trim().split("\\s+");
        if (parts.length < 2) {
            return 0;
        }
        try {
            return Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static long parseLong(String value) {
        if (value == null || value.isBlank()) {
            return 0;
        }
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static Document parseXml(byte[] body, URI uri) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            factory.setNamespaceAware(true);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            builder.setEntityResolver((publicId, systemId) ->
                    new org.xml.sax.InputSource(new java.io.StringReader("")));
            return builder.parse(new ByteArrayInputStream(body));
        } catch (ParserConfigurationException e) {
            throw new XrdException("the JDK XML parser refused a safe configuration", e);
        } catch (SAXException | IOException e) {
            throw new XrdException("PROPFIND " + uri + " returned unreadable XML: "
                    + e.getMessage(), e);
        }
    }

    private static Element child(Element parent, String name) {
        if (parent == null) {
            return null;
        }
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node node = children.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE
                    && DAV.equals(node.getNamespaceURI())
                    && name.equals(node.getLocalName())) {
                return (Element) node;
            }
        }
        return null;
    }

    private static String text(Element element) {
        return element == null ? null : element.getTextContent();
    }

    /** An href is a URL or an absolute path, and is percent-encoded either way. */
    static String pathOf(String href, URI base) {
        String trimmed = href.trim();
        try {
            URI resolved = base.resolve(new URI(trimmed));
            String path = resolved.getPath();
            if (path != null) {
                return path;
            }
        } catch (URISyntaxException e) {
            // a server that sent a raw space or brace; decode what we can
        }
        return URLDecoder.decode(trimmed, StandardCharsets.UTF_8);
    }

    private static String trimSlash(String path) {
        if (path == null || path.isEmpty()) {
            return "/";
        }
        return path.length() > 1 && path.endsWith("/")
                ? path.substring(0, path.length() - 1)
                : path;
    }

    private static String nameOf(String path) {
        int slash = path.lastIndexOf('/');
        return slash < 0 ? path : path.substring(slash + 1);
    }

    /** Every ancestor of {@code uri}'s path, shallowest first, as absolute paths. */
    private static List<String> ancestors(URI uri) {
        String path = trimSlash(uri.getPath());
        List<String> out = new ArrayList<>();
        StringBuilder walked = new StringBuilder();
        String[] parts = path.split("/");
        for (int i = 1; i < parts.length - 1; i++) {   // skip the leaf and the leading ""
            if (parts[i].isEmpty()) {
                continue;
            }
            walked.append('/').append(parts[i]);
            out.add(walked + "/");
        }
        return out;
    }

    @Override
    public String toString() {
        return "WebDav[" + (tokenOrNull() != null ? "bearer" : "no token") + "]";
    }
}

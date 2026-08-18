package io.github.robc.jroot.client;

import java.io.Closeable;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdException;
import io.github.robc.jroot.XrdServerException;
import io.github.robc.jroot.wire.Requests;
import io.github.robc.jroot.wire.Responses;
import io.github.robc.jroot.wire.Types.ChecksumInfo;
import io.github.robc.jroot.wire.Types.DirEntry;
import io.github.robc.jroot.wire.Types.FattrResult;
import io.github.robc.jroot.wire.Types.LocationInfo;
import io.github.robc.jroot.wire.Types.OpenInfo;
import io.github.robc.jroot.wire.Types.RedirectInfo;
import io.github.robc.jroot.wire.Types.SpaceInfo;
import io.github.robc.jroot.wire.Types.StatInfo;
import io.github.robc.jroot.wire.Types.VfsInfo;
import io.github.robc.jroot.wire.XrdConst;

/**
 * The {@code root://} filesystem: connections, redirects and the operations
 * that do not need an open file.
 *
 * <p>A cluster answers most requests with {@code kXR_redirect} — the manager
 * knows which data server holds the file and says so — which is why nothing
 * here talks to a connection directly. Every operation runs through
 * {@link #execute}, which follows redirects, carries the server's opaque
 * information onto the next request, and reuses connections it has already
 * brought up. Instances are thread-safe and worth sharing: the connection
 * cache is the point.
 */
public final class XrdClient implements Closeable {

    private final Config config;
    private final Map<String, XrdConnection> connections = new ConcurrentHashMap<>();

    public XrdClient() {
        this(Config.defaults());
    }

    public XrdClient(Config config) {
        this.config = config;
    }

    public Config config() {
        return config;
    }

    /** One operation, retried at whatever server the cluster points it to. */
    @FunctionalInterface
    public interface Operation<T> {
        T run(XrdConnection connection, XrdUrl url);
    }

    /** The connection to {@code url}'s server, brought up if there is not one. */
    public XrdConnection connection(XrdUrl url) {
        XrdConnection existing = connections.get(url.serverKey());
        if (existing != null && existing.isOpen()) {
            return existing;
        }
        XrdConnection opened = XrdConnection.open(url, config);
        XrdConnection raced = connections.put(url.serverKey(), opened);
        if (raced != null && raced != opened) {
            raced.close();
        }
        return opened;
    }

    /**
     * Run {@code operation} against {@code url}, following redirects until
     * a server answers or the limit is reached.
     */
    public <T> T execute(XrdUrl url, Operation<T> operation) {
        XrdUrl current = url;
        for (int hop = 0; hop <= config.maxRedirects(); hop++) {
            try {
                return operation.run(connection(current), current);
            } catch (XrdRedirectException e) {
                current = follow(current, e.redirect());
            }
        }
        throw new XrdException(url + " redirected more than " + config.maxRedirects()
                + " times; the cluster is looping");
    }

    /**
     * Where a redirect points. The opaque information the server attached
     * travels with the request from here on — it is how a manager tells the
     * data server what it already decided.
     */
    static XrdUrl follow(XrdUrl url, RedirectInfo redirect) {
        XrdUrl next = url.at(redirect.host(), redirect.actualPort(), redirect.requiresTls());
        if (redirect.opaque().isEmpty()) {
            return next;
        }
        String opaque = redirect.opaque();
        while (!opaque.isEmpty() && (opaque.charAt(0) == '&' || opaque.charAt(0) == '?')) {
            opaque = opaque.substring(1);
        }
        String cgi = url.cgi().isEmpty() ? opaque : url.cgi() + "&" + opaque;
        return next.withCgi(cgi);
    }

    // -----------------------------------------------------------------
    // Metadata
    // -----------------------------------------------------------------

    public StatInfo stat(String url) {
        return stat(XrdUrl.parse(url));
    }

    public StatInfo stat(XrdUrl url) {
        return execute(url, (connection, at) -> Responses.parseStat(
                connection.request(new Requests.Stat(at.pathWithCgi())).data(), at.path()));
    }

    /** Whether a path exists, without making its absence an exception. */
    public boolean exists(String url) {
        try {
            stat(url);
            return true;
        } catch (XrdServerException e) {
            if (e.isNotFound()) {
                return false;
            }
            throw e;
        }
    }

    public Optional<StatInfo> statIfPresent(String url) {
        try {
            return Optional.of(stat(url));
        } catch (XrdServerException e) {
            if (e.isNotFound()) {
                return Optional.empty();
            }
            throw e;
        }
    }

    /** Free space where {@code url} lives. */
    public VfsInfo statVfs(String url) {
        XrdUrl parsed = XrdUrl.parse(url);
        return execute(parsed, (connection, at) -> Responses.parseStatVfs(
                connection.request(new Requests.Stat(at.pathWithCgi(),
                        XrdConst.kXR_vfs, XrdConst.NULL_FHANDLE)).data()));
    }

    /** One flags byte per path, in the order given. */
    public int[] statx(List<String> paths) {
        if (paths.isEmpty()) {
            return new int[0];
        }
        XrdUrl first = XrdUrl.parse(paths.get(0));
        List<String> onlyPaths = paths.stream().map(p -> XrdUrl.parse(p).path()).toList();
        return execute(first, (connection, at) ->
                Responses.parseStatx(connection.request(new Requests.Statx(onlyPaths)).data()));
    }

    /** List a directory. Stat information is requested and used when the
     *  server offers it, which turns an {@code ls -l} into one round trip. */
    public List<DirEntry> list(String url) {
        return list(XrdUrl.parse(url), true);
    }

    public List<DirEntry> list(XrdUrl url, boolean withStat) {
        int options = withStat ? XrdConst.kXR_dstat : 0;
        return execute(url, (connection, at) -> Responses.parseDirlist(
                connection.request(new Requests.Dirlist(at.pathWithCgi(), options)).data(),
                at.path()));
    }

    public List<LocationInfo> locate(String url) {
        return locate(XrdUrl.parse(url), 0);
    }

    public List<LocationInfo> locate(XrdUrl url, int options) {
        return execute(url, (connection, at) -> Responses.parseLocate(
                connection.request(new Requests.Locate(at.pathWithCgi(), options)).data()));
    }

    public ChecksumInfo checksum(String url) {
        XrdUrl parsed = XrdUrl.parse(url);
        return execute(parsed, (connection, at) -> Responses.parseChecksum(
                connection.request(new Requests.Query(XrdConst.kXR_Qcksum,
                        at.pathWithCgi())).data()));
    }

    public SpaceInfo space(String url) {
        XrdUrl parsed = XrdUrl.parse(url);
        return execute(parsed, (connection, at) -> Responses.parseSpace(
                connection.request(new Requests.Query(XrdConst.kXR_Qspace,
                        at.pathWithCgi())).data()));
    }

    /** A raw {@code kXR_query}, for the information types this API does not name. */
    public String query(String url, int infotype, String args) {
        XrdUrl parsed = XrdUrl.parse(url);
        return execute(parsed, (connection, at) -> new String(
                connection.request(new Requests.Query(infotype, args)).data(),
                StandardCharsets.UTF_8).trim());
    }

    public String config(String url, String what) {
        return query(url, XrdConst.kXR_Qconfig, what);
    }

    // -----------------------------------------------------------------
    // Namespace
    // -----------------------------------------------------------------

    public void mkdir(String url, int mode, boolean makePath) {
        XrdUrl parsed = XrdUrl.parse(url);
        execute(parsed, (connection, at) ->
                connection.request(new Requests.Mkdir(at.pathWithCgi(), mode, makePath)));
    }

    public void mkdir(String url) {
        mkdir(url, XrdConst.DEFAULT_DIR_MODE, true);
    }

    public void rm(String url) {
        XrdUrl parsed = XrdUrl.parse(url);
        execute(parsed, (connection, at) ->
                connection.request(new Requests.Rm(at.pathWithCgi())));
    }

    public void rmdir(String url) {
        XrdUrl parsed = XrdUrl.parse(url);
        execute(parsed, (connection, at) ->
                connection.request(new Requests.Rmdir(at.pathWithCgi())));
    }

    /** Rename within one server. Both paths must live on the same server —
     *  the protocol has no notion of moving between them. */
    public void mv(String sourceUrl, String targetUrl) {
        XrdUrl source = XrdUrl.parse(sourceUrl);
        XrdUrl target = XrdUrl.parse(targetUrl);
        if (!source.endpoint().equals(target.endpoint())) {
            throw new XrdException("kXR_mv cannot move between servers: "
                    + source.endpoint() + " and " + target.endpoint());
        }
        execute(source, (connection, at) ->
                connection.request(new Requests.Mv(at.path(), target.path())));
    }

    public void chmod(String url, int mode) {
        XrdUrl parsed = XrdUrl.parse(url);
        execute(parsed, (connection, at) ->
                connection.request(new Requests.Chmod(at.pathWithCgi(), mode)));
    }

    public void truncate(String url, long size) {
        XrdUrl parsed = XrdUrl.parse(url);
        execute(parsed, (connection, at) -> connection.request(
                new Requests.Truncate(at.pathWithCgi(), size, XrdConst.NULL_FHANDLE)));
    }

    /** Ask a staging server to bring files online. Returns its request handle. */
    public String prepare(List<String> urls, int options, int priority) {
        if (urls.isEmpty()) {
            return "";
        }
        XrdUrl first = XrdUrl.parse(urls.get(0));
        List<String> paths = urls.stream().map(u -> XrdUrl.parse(u).pathWithCgi()).toList();
        return execute(first, (connection, at) -> new String(
                connection.request(new Requests.Prepare(paths, options, priority, 0, 0)).data(),
                StandardCharsets.UTF_8).trim());
    }

    // -----------------------------------------------------------------
    // Extended attributes
    // -----------------------------------------------------------------

    public FattrResult getAttribute(String url, String name) {
        XrdUrl parsed = XrdUrl.parse(url);
        return execute(parsed, (connection, at) -> Responses.parseFattr(
                connection.request(Requests.Fattr.get(at.path(), name)).data(), true));
    }

    public FattrResult listAttributes(String url, boolean withValues) {
        XrdUrl parsed = XrdUrl.parse(url);
        return execute(parsed, (connection, at) -> Responses.parseFattr(
                connection.request(Requests.Fattr.list(at.path(), withValues)).data(),
                withValues));
    }

    public void setAttribute(String url, String name, byte[] value) {
        XrdUrl parsed = XrdUrl.parse(url);
        execute(parsed, (connection, at) ->
                connection.request(Requests.Fattr.set(at.path(), name, value, false)));
    }

    public void deleteAttribute(String url, String name) {
        XrdUrl parsed = XrdUrl.parse(url);
        execute(parsed, (connection, at) ->
                connection.request(Requests.Fattr.delete(at.path(), name)));
    }

    // -----------------------------------------------------------------
    // Files
    // -----------------------------------------------------------------

    /** Open for reading. */
    public XrdFile open(String url) {
        return open(url, XrdConst.kXR_open_read | XrdConst.kXR_retstat, 0);
    }

    /** Create or truncate for writing, making parent directories. */
    public XrdFile create(String url, int mode) {
        return open(url, XrdConst.kXR_open_updt | XrdConst.kXR_delete
                | XrdConst.kXR_mkpath | XrdConst.kXR_retstat, mode);
    }

    public XrdFile open(String url, int options, int mode) {
        return open(XrdUrl.parse(url), options, mode);
    }

    public XrdFile open(XrdUrl url, int options, int mode) {
        return execute(url, (connection, at) -> {
            OpenInfo info = Responses.parseOpen(
                    connection.request(new Requests.Open(at.pathWithCgi(), options, mode)).data(),
                    at.path());
            return new XrdFile(connection, at, info);
        });
    }

    /** Read a whole file. */
    public byte[] read(String url) {
        try (XrdFile file = open(url)) {
            return file.readAll(8 << 20);
        }
    }

    /** Write a whole file, replacing anything already there. */
    public void write(String url, byte[] data, int mode) {
        try (XrdFile file = create(url, mode)) {
            file.write(0, data);
        }
    }

    public void write(String url, byte[] data) {
        write(url, data, 0644);
    }

    /** A round trip to prove the connection is alive. */
    public void ping(String url) {
        XrdUrl parsed = XrdUrl.parse(url);
        execute(parsed, (connection, at) -> connection.request(new Requests.Ping()));
    }

    /**
     * {@code kXR_set}: tell a server something about this client. The one
     * directive worth sending is {@code appid <name>}, which is what a site
     * sees beside this client's requests in its logs.
     */
    public void set(String url, String directive) {
        XrdUrl parsed = XrdUrl.parse(url);
        execute(parsed, (connection, at) -> connection.request(new Requests.Set(directive)));
    }

    @Override
    public void close() {
        for (XrdConnection connection : connections.values()) {
            connection.close();
        }
        connections.clear();
    }

    @Override
    public String toString() {
        return "XrdClient" + connections.keySet();
    }
}

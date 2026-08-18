package io.github.robc.jroot.http;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdConnectionException;
import io.github.robc.jroot.XrdException;
import io.github.robc.jroot.XrdServerException;
import io.github.robc.jroot.auth.TokenCredential;
import io.github.robc.jroot.client.TlsFactory;
import io.github.robc.jroot.wire.Types;
import io.github.robc.jroot.wire.Types.StatInfo;
import io.github.robc.jroot.wire.XrdConst;

/**
 * The HTTP transport — XRootD-HTTP and, through {@link WebDav}, WebDAV.
 *
 * <p>Authentication is the same material the binary protocol uses, offered
 * the way HTTP expects it: a bearer token in an {@code Authorization}
 * header, and an X.509 proxy as the client certificate of the TLS
 * handshake, which is what GSI over HTTPS amounts to. Redirects are
 * followed here rather than by {@link HttpClient} because a storage
 * redirect is the normal case — the manager sends every transfer to a data
 * node — and because the JDK's own follower drops the {@code Authorization}
 * header, which those data nodes need.
 *
 * <p>Server errors surface as {@link XrdServerException} carrying the
 * equivalent {@code kXR_} code, so a caller can handle "not found" the same
 * way whichever protocol produced it.
 */
public class HttpStorage implements AutoCloseable {

    /** RFC 7231 dates, which is what {@code Last-Modified} carries. */
    private static final DateTimeFormatter HTTP_DATE =
            DateTimeFormatter.RFC_1123_DATE_TIME;

    protected final Config config;
    protected final HttpClient http;
    private final String token;

    public HttpStorage(Config config) {
        this.config = config;
        this.token = config.token() != null && !config.token().isBlank()
                ? config.token().strip()
                : TokenCredential.discover().orElse(null);
        this.http = HttpClient.newBuilder()
                .connectTimeout(config.connectTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .sslContext(TlsFactory.create(config))
                .build();
    }

    /** Whether this transport handles {@code scheme}. */
    public static boolean handles(String scheme) {
        return scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https")
                || scheme.equalsIgnoreCase("dav") || scheme.equalsIgnoreCase("davs");
    }

    /** {@code dav://} and {@code davs://} are WebDAV spellings of HTTP(S). */
    public static URI normalise(String url) {
        URI uri = URI.create(url);
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase();
        return switch (scheme) {
            case "dav" -> withScheme(uri, "http");
            case "davs" -> withScheme(uri, "https");
            default -> uri;
        };
    }

    private static URI withScheme(URI uri, String scheme) {
        return URI.create(scheme + uri.toString().substring(uri.getScheme().length()));
    }

    // -----------------------------------------------------------------
    // Operations
    // -----------------------------------------------------------------

    /** {@code HEAD}: size, modification time and whether this is a collection. */
    public StatInfo stat(String url) {
        URI uri = normalise(url);
        HttpResponse<Void> response = send(builder(uri).method("HEAD",
                BodyPublishers.noBody()), BodyHandlers.discarding(), uri);
        check(response, uri, "HEAD");
        long size = response.headers().firstValueAsLong("content-length").orElse(0);
        long mtime = response.headers().firstValue("last-modified")
                .map(HttpStorage::parseHttpDate).orElse(0L);
        boolean directory = uri.getPath().endsWith("/")
                || response.headers().firstValue("content-type")
                        .map(type -> type.startsWith("text/html")).orElse(false);
        int flags = XrdConst.kXR_readable | (directory ? XrdConst.kXR_isDir : 0);
        return new StatInfo("", size, flags, mtime, uri.getPath());
    }

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

    /** {@code GET} the whole object. */
    public byte[] read(String url) {
        URI uri = normalise(url);
        HttpResponse<byte[]> response =
                send(builder(uri).GET(), BodyHandlers.ofByteArray(), uri);
        check(response, uri, "GET");
        return limit(response.body(), uri);
    }

    /** {@code GET} with a {@code Range} header: {@code length} bytes at
     *  {@code offset}. A server that ignores the range is not humoured. */
    public byte[] read(String url, long offset, int length) {
        if (length <= 0) {
            return new byte[0];
        }
        URI uri = normalise(url);
        HttpResponse<byte[]> response = send(builder(uri).GET()
                .header("Range", "bytes=" + offset + "-" + (offset + length - 1)),
                BodyHandlers.ofByteArray(), uri);
        check(response, uri, "GET");
        byte[] body = limit(response.body(), uri);
        if (response.statusCode() == 200 && body.length > length) {
            throw new XrdException(uri.getHost()
                    + " ignored the Range header and sent the whole object");
        }
        return body;
    }

    /**
     * Several ranges in one request — the HTTP spelling of {@code kXR_readv},
     * and the reason a columnar read of a remote file costs one round trip
     * rather than one per column.
     *
     * <p>A server may answer three ways: {@code multipart/byteranges} with a
     * part per range, a single {@code Content-Range} when it coalesced them,
     * or {@code 200} with the whole object when it does not do ranges at all.
     * The first two are unpacked; the third is refused, because silently
     * returning the wrong bytes is worse than failing.
     */
    public List<Types.ReadVSegment> readV(String url, List<long[]> ranges) {
        if (ranges.isEmpty()) {
            return List.of();
        }
        URI uri = normalise(url);
        StringBuilder spec = new StringBuilder("bytes=");
        for (int i = 0; i < ranges.size(); i++) {
            long[] range = ranges.get(i);
            if (i > 0) {
                spec.append(", ");
            }
            spec.append(range[0]).append('-').append(range[0] + range[1] - 1);
        }
        HttpResponse<byte[]> response = send(builder(uri).GET()
                .header("Range", spec.toString()), BodyHandlers.ofByteArray(), uri);
        check(response, uri, "GET");
        byte[] body = limit(response.body(), uri);
        if (response.statusCode() != 206) {
            throw new XrdException(uri + " answered " + response.statusCode()
                    + " to a multi-range request instead of 206 Partial Content");
        }
        String contentType = response.headers().firstValue("content-type").orElse("");
        if (!contentType.toLowerCase().startsWith("multipart/byteranges")) {
            long start = response.headers().firstValue("content-range")
                    .map(HttpStorage::rangeStart).orElse(ranges.get(0)[0]);
            return List.of(new Types.ReadVSegment(NO_HANDLE, start, body));
        }
        return parseByteRanges(body, boundaryOf(contentType, uri), uri);
    }

    /** {@code PUT} the whole object. */
    public void write(String url, byte[] data) {
        URI uri = normalise(url);
        HttpRequest.BodyPublisher body = BodyPublishers.ofByteArray(data);
        HttpResponse<Void> response = send(builder(uri).PUT(body)
                .header("Content-Type", "application/octet-stream"),
                BodyHandlers.discarding(), uri, body);
        check(response, uri, "PUT");
    }

    /**
     * {@code PUT} a local file, streamed rather than buffered — the usual
     * shape of an upload, and the only one that works for objects larger
     * than the heap. The publisher re-reads the file if the door redirects
     * the transfer to a data node, which is the normal case.
     */
    public void write(String url, Path file) {
        URI uri = normalise(url);
        HttpRequest.BodyPublisher body;
        try {
            body = BodyPublishers.ofFile(file);
        } catch (java.io.FileNotFoundException e) {
            throw new XrdException("cannot read " + file + ": " + e.getMessage(), e);
        }
        HttpResponse<Void> response = send(builder(uri).PUT(body)
                .header("Content-Type", "application/octet-stream"),
                BodyHandlers.discarding(), uri, body);
        check(response, uri, "PUT");
    }

    /** {@code GET} straight to a local file, without holding it in memory. */
    public long readTo(String url, Path target) {
        URI uri = normalise(url);
        HttpResponse<Path> response = send(builder(uri).GET(),
                BodyHandlers.ofFile(target, StandardOpenOption.CREATE,
                        StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING),
                uri);
        check(response, uri, "GET");
        try {
            return Files.size(response.body());
        } catch (IOException e) {
            throw new XrdException("cannot size " + target + ": " + e.getMessage(), e);
        }
    }

    public void delete(String url) {
        URI uri = normalise(url);
        HttpResponse<Void> response =
                send(builder(uri).DELETE(), BodyHandlers.discarding(), uri);
        check(response, uri, "DELETE");
    }

    /** The checksum a server will compute, via the {@code Want-Digest}
     *  negotiation WLCG storage speaks. */
    public Optional<String> checksum(String url, String algorithm) {
        URI uri = normalise(url);
        HttpResponse<Void> response = send(builder(uri)
                .method("HEAD", BodyPublishers.noBody())
                .header("Want-Digest", algorithm), BodyHandlers.discarding(), uri);
        check(response, uri, "HEAD");
        return response.headers().firstValue("digest");
    }

    // -----------------------------------------------------------------
    // Plumbing
    // -----------------------------------------------------------------

    protected HttpRequest.Builder builder(URI uri) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .timeout(config.requestTimeout());
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        return builder;
    }

    /**
     * Send a request, following storage redirects by hand.
     *
     * <p>The bearer token travels to the redirect target — data nodes are
     * given transfers on the strength of it — except where the redirect
     * downgrades {@code https} to {@code http}, which would put the token
     * on the wire in clear. That one is refused rather than downgraded
     * silently.
     */
    protected <T> HttpResponse<T> send(HttpRequest.Builder builder,
                                       HttpResponse.BodyHandler<T> handler, URI uri) {
        return send(builder, handler, uri, null);
    }

    /**
     * As {@link #send}, with a body this client is allowed to send again if
     * the request is redirected. WebDAV needs it — a PROPFIND carries its
     * property list in the body and doors do redirect them.
     */
    protected <T> HttpResponse<T> send(HttpRequest.Builder builder,
                                       HttpResponse.BodyHandler<T> handler, URI uri,
                                       HttpRequest.BodyPublisher replayBody) {
        HttpRequest request = builder.build();
        for (int hop = 0; hop <= config.maxRedirects(); hop++) {
            HttpResponse<T> response;
            try {
                response = http.send(request, handler);
            } catch (IOException e) {
                throw new XrdConnectionException(request.method() + " " + request.uri()
                        + " failed: " + e.getMessage(), e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new XrdConnectionException("interrupted during "
                        + request.method() + " " + request.uri(), e);
            }
            if (!isRedirect(response.statusCode())) {
                return response;
            }
            HttpRequest sent = request;
            URI target = response.headers().firstValue("location")
                    .map(location -> sent.uri().resolve(location))
                    .orElseThrow(() -> new XrdException(sent.uri()
                            + " answered " + response.statusCode() + " with no Location"));
            if ("https".equalsIgnoreCase(request.uri().getScheme())
                    && "http".equalsIgnoreCase(target.getScheme())) {
                throw new XrdException(request.uri()
                        + " redirected to plain HTTP at " + target
                        + ", which would put credentials in clear");
            }
            request = redirected(request, target, response.statusCode(), replayBody);
        }
        throw new XrdException(uri + " redirected more than " + config.maxRedirects() + " times");
    }

    private HttpRequest redirected(HttpRequest request, URI target, int status,
                                   HttpRequest.BodyPublisher replayBody) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(target)
                .timeout(request.timeout().orElse(config.requestTimeout()));
        request.headers().map().forEach((name, values) ->
                values.forEach(value -> builder.header(name, value)));
        // 303 turns anything into a GET; 307 and 308 keep the method, and a
        // body can only be sent again if the caller handed us the bytes.
        if (status == 303) {
            return builder.GET().build();
        }
        if (replayBody != null) {
            return builder.method(request.method(), replayBody).build();
        }
        if (request.bodyPublisher().map(publisher -> publisher.contentLength() != 0)
                .orElse(false)) {
            throw new XrdException(request.method() + " " + request.uri()
                    + " was redirected with a body, which this client will not replay");
        }
        return builder.method(request.method(), BodyPublishers.noBody()).build();
    }

    private static boolean isRedirect(int status) {
        return status == 301 || status == 302 || status == 303
                || status == 307 || status == 308;
    }

    private byte[] limit(byte[] body, URI uri) {
        if (body.length > XrdConst.MAX_RESPONSE_BODY) {
            throw new XrdException(uri + " returned " + body.length
                    + " bytes, past the " + XrdConst.MAX_RESPONSE_BODY + " this client buffers");
        }
        return body;
    }

    /** Turn a failing status into the {@code kXR_} error a caller can act on. */
    protected void check(HttpResponse<?> response, URI uri, String method) {
        int status = response.statusCode();
        if (status >= 200 && status < 300) {
            return;
        }
        throw new XrdServerException(codeFor(status),
                method + " " + uri + " answered " + status + " " + reason(status));
    }

    static int codeFor(int status) {
        return switch (status) {
            case 400 -> XrdConst.kXR_ArgInvalid;
            case 401, 403 -> XrdConst.kXR_NotAuthorized;
            case 404, 409, 410 -> XrdConst.kXR_NotFound;
            case 405, 501 -> XrdConst.kXR_Unsupported;
            case 412 -> XrdConst.kXR_ItExists;
            case 423, 429, 503 -> XrdConst.kXR_FileLocked;
            case 507 -> XrdConst.kXR_NoSpace;
            default -> status >= 500 ? XrdConst.kXR_ServerError : XrdConst.kXR_ArgInvalid;
        };
    }

    private static String reason(int status) {
        return switch (status) {
            case 400 -> "Bad Request";
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            case 409 -> "Conflict";
            case 412 -> "Precondition Failed";
            case 423 -> "Locked";
            case 429 -> "Too Many Requests";
            case 500 -> "Internal Server Error";
            case 501 -> "Not Implemented";
            case 503 -> "Service Unavailable";
            case 507 -> "Insufficient Storage";
            default -> "";
        };
    }

    /** An HTTP range reply carries no file handle; the binary protocol's
     *  record has one, so it is filled with nothing. */
    private static final byte[] NO_HANDLE = new byte[0];

    /** {@code multipart/byteranges; boundary=abc} → {@code abc}. */
    static String boundaryOf(String contentType, URI uri) {
        for (String part : contentType.split(";")) {
            String trimmed = part.trim();
            if (trimmed.regionMatches(true, 0, "boundary=", 0, 9)) {
                String boundary = trimmed.substring(9).trim();
                if (boundary.length() >= 2 && boundary.startsWith("\"") && boundary.endsWith("\"")) {
                    boundary = boundary.substring(1, boundary.length() - 1);
                }
                if (!boundary.isEmpty()) {
                    return boundary;
                }
            }
        }
        throw new XrdException(uri + " sent multipart/byteranges with no boundary");
    }

    /** {@code bytes 100-199/4096} → 100. */
    static long rangeStart(String contentRange) {
        String value = contentRange.trim();
        int space = value.indexOf(' ');
        if (space > 0) {
            value = value.substring(space + 1);
        }
        int dash = value.indexOf('-');
        if (dash <= 0) {
            return 0;
        }
        try {
            return Long.parseLong(value.substring(0, dash).trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /**
     * Split a {@code multipart/byteranges} body. Parsed over bytes rather
     * than a decoded string: the parts are file contents, and decoding them
     * as text would corrupt anything that is not UTF-8.
     */
    static List<Types.ReadVSegment> parseByteRanges(byte[] body, String boundary, URI uri) {
        byte[] delimiter = ("--" + boundary).getBytes(StandardCharsets.ISO_8859_1);
        List<Types.ReadVSegment> out = new ArrayList<>();
        int at = indexOf(body, delimiter, 0);
        if (at < 0) {
            throw new XrdException(uri + " sent a multipart body without its boundary");
        }
        while (at >= 0) {
            int cursor = at + delimiter.length;
            if (cursor + 1 < body.length && body[cursor] == '-' && body[cursor + 1] == '-') {
                break;                                  // the closing delimiter
            }
            int headerEnd = endOfHeaders(body, cursor);
            if (headerEnd < 0) {
                throw new XrdException(uri + " sent a multipart part with no header break");
            }
            String headers = new String(body, cursor, headerEnd - cursor,
                    StandardCharsets.ISO_8859_1);
            int next = indexOf(body, delimiter, headerEnd);
            int end = next < 0 ? body.length : next;
            // The CRLF before the next delimiter belongs to the delimiter,
            // not to the data.
            while (end > headerEnd && (body[end - 1] == '\n' || body[end - 1] == '\r')) {
                end--;
            }
            byte[] data = new byte[end - headerEnd];
            System.arraycopy(body, headerEnd, data, 0, data.length);
            out.add(new Types.ReadVSegment(NO_HANDLE, startOf(headers), data));
            at = next;
        }
        return out;
    }

    private static long startOf(String headers) {
        for (String line : headers.split("\r?\n")) {
            if (line.regionMatches(true, 0, "content-range:", 0, 14)) {
                return rangeStart(line.substring(14));
            }
        }
        return 0;
    }

    /** The offset just past the blank line that ends a part's headers. */
    private static int endOfHeaders(byte[] body, int from) {
        for (int i = from; i + 1 < body.length; i++) {
            if (body[i] == '\n' && body[i + 1] == '\n') {
                return i + 2;
            }
            if (i + 3 < body.length && body[i] == '\r' && body[i + 1] == '\n'
                    && body[i + 2] == '\r' && body[i + 3] == '\n') {
                return i + 4;
            }
        }
        return -1;
    }

    private static int indexOf(byte[] haystack, byte[] needle, int from) {
        outer:
        for (int i = Math.max(from, 0); i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    static long parseHttpDate(String value) {
        try {
            return ZonedDateTime.parse(value, HTTP_DATE).toEpochSecond();
        } catch (DateTimeParseException e) {
            return 0;
        }
    }

    protected String tokenOrNull() {
        return token;
    }

    /** How long a request may take, for callers building their own. */
    public Duration requestTimeout() {
        return config.requestTimeout();
    }

    @Override
    public void close() {
        // HttpClient holds only its own executor, which the JDK reclaims;
        // the method exists so callers can use try-with-resources uniformly.
    }

    @Override
    public String toString() {
        return "HttpStorage[" + (token != null ? "bearer" : "no token") + "]";
    }

    static String utf8(byte[] data) {
        return new String(data, StandardCharsets.UTF_8);
    }
}

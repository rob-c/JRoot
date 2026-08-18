package io.github.robc.jroot.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * An HTTP and WebDAV storage endpoint, built on the JDK's own server so the
 * client under test talks to a real socket. It keeps files in a map and
 * answers the verbs XRootD-HTTP and WebDAV storage answer, including the
 * awkward ones: multipart byte ranges, a door that redirects to a data node,
 * and a third-party copy that reports its outcome in the body.
 */
public final class MockHttpStorage implements AutoCloseable {

    private final HttpServer server;
    private final Map<String, byte[]> files = new LinkedHashMap<>();
    private final Set<String> collections = new LinkedHashSet<>();
    private final List<String> log = new CopyOnWriteArrayList<>();
    private final List<Headers> requestHeaders = new CopyOnWriteArrayList<>();
    private volatile String redirectTo;
    private volatile String copyOutcome = "success: Created";
    private final java.util.concurrent.atomic.AtomicInteger failFirst =
            new java.util.concurrent.atomic.AtomicInteger();

    public MockHttpStorage() throws IOException {
        server = HttpServer.create(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 8);
        server.createContext("/", this::dispatch);
        server.setExecutor(null);
        server.start();
        collections.add("/");
    }

    public String url(String path) {
        return "http://" + server.getAddress().getAddress().getHostAddress()
                + ":" + server.getAddress().getPort() + path;
    }

    public MockHttpStorage put(String path, byte[] content) {
        files.put(path, content);
        return this;
    }

    /** Answer the next {@code count} GETs with a 500, as a door under load does. */
    public MockHttpStorage failingFirstReads(int count) {
        failFirst.set(count);
        return this;
    }

    public MockHttpStorage collection(String path) {
        collections.add(path);
        return this;
    }

    public byte[] contentOf(String path) {
        return files.get(path);
    }

    public boolean has(String path) {
        return files.containsKey(path) || collections.contains(path);
    }

    public List<String> log() {
        return List.copyOf(log);
    }

    public List<Headers> headers() {
        return List.copyOf(requestHeaders);
    }

    /** Make the next requests answer 307 to {@code target} before serving. */
    public MockHttpStorage redirectingTo(String target) {
        redirectTo = target;
        return this;
    }

    public MockHttpStorage copyEnding(String outcome) {
        copyOutcome = outcome;
        return this;
    }

    /** Answer COPY with an empty body, as a server cut off mid-transfer does. */
    public MockHttpStorage copySilent() {
        copyOutcome = null;
        return this;
    }

    // -----------------------------------------------------------------

    private void dispatch(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
        log.add(method + " " + path);
        requestHeaders.add(exchange.getRequestHeaders());
        try (exchange) {
            String target = redirectTo;
            if (target != null && !method.equals("COPY")) {
                redirectTo = null;
                exchange.getResponseHeaders().add("Location", target);
                exchange.sendResponseHeaders(307, -1);
                return;
            }
            if (method.equals("GET") && failFirst.getAndUpdate(n -> Math.max(0, n - 1)) > 0) {
                exchange.sendResponseHeaders(500, -1);
                return;
            }
            switch (method) {
                case "GET" -> get(exchange, path);
                case "HEAD" -> head(exchange, path);
                case "PUT" -> put(exchange, path);
                case "DELETE" -> delete(exchange, path);
                case "PROPFIND" -> propfind(exchange, path);
                case "MKCOL" -> mkcol(exchange, path);
                case "MOVE" -> move(exchange, path);
                case "COPY" -> copy(exchange);
                default -> exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    private void get(HttpExchange exchange, String path) throws IOException {
        byte[] content = files.get(path);
        if (content == null) {
            exchange.sendResponseHeaders(404, -1);
            return;
        }
        String range = exchange.getRequestHeaders().getFirst("Range");
        if (range == null) {
            send(exchange, 200, content, "application/octet-stream");
            return;
        }
        List<long[]> ranges = parseRanges(range, content.length);
        if (ranges.size() == 1) {
            long[] one = ranges.get(0);
            byte[] slice = slice(content, one);
            exchange.getResponseHeaders().add("Content-Range",
                    "bytes " + one[0] + "-" + (one[0] + slice.length - 1) + "/" + content.length);
            send(exchange, 206, slice, "application/octet-stream");
            return;
        }
        String boundary = "3d6b6a416f9b5";
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (long[] one : ranges) {
            byte[] slice = slice(content, one);
            body.write(("--" + boundary + "\r\nContent-Type: application/octet-stream\r\n"
                    + "Content-Range: bytes " + one[0] + "-" + (one[0] + slice.length - 1)
                    + "/" + content.length + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
            body.write(slice);
            body.write("\r\n".getBytes(StandardCharsets.ISO_8859_1));
        }
        body.write(("--" + boundary + "--\r\n").getBytes(StandardCharsets.ISO_8859_1));
        send(exchange, 206, body.toByteArray(), "multipart/byteranges; boundary=" + boundary);
    }

    private static byte[] slice(byte[] content, long[] range) {
        int from = (int) Math.min(range[0], content.length);
        int to = (int) Math.min(range[1] + 1, content.length);
        byte[] out = new byte[Math.max(to - from, 0)];
        System.arraycopy(content, from, out, 0, out.length);
        return out;
    }

    private static List<long[]> parseRanges(String header, int size) {
        List<long[]> out = new ArrayList<>();
        String spec = header.substring(header.indexOf('=') + 1);
        for (String part : spec.split(",")) {
            String[] ends = part.trim().split("-", -1);
            long from = Long.parseLong(ends[0].trim());
            long to = ends.length > 1 && !ends[1].isBlank()
                    ? Long.parseLong(ends[1].trim()) : size - 1;
            out.add(new long[] {from, to});
        }
        return out;
    }

    private void head(HttpExchange exchange, String path) throws IOException {
        byte[] content = files.get(path);
        if (content == null && !collections.contains(path)) {
            exchange.sendResponseHeaders(404, -1);
            return;
        }
        Headers headers = exchange.getResponseHeaders();
        headers.add("Last-Modified", "Tue, 15 Nov 2022 12:45:26 GMT");
        if (exchange.getRequestHeaders().containsKey("Want-Digest")) {
            headers.add("Digest", "adler32=" + adler32(content));
        }
        headers.add("Content-Length", String.valueOf(content == null ? 0 : content.length));
        exchange.sendResponseHeaders(200, -1);
    }

    /** What real storage answers Want-Digest with: the object's own checksum. */
    public static String adler32(byte[] content) {
        java.util.zip.Adler32 sum = new java.util.zip.Adler32();
        sum.update(content == null ? new byte[0] : content);
        return String.format("%08x", sum.getValue());
    }

    private void put(HttpExchange exchange, String path) throws IOException {
        files.put(path, exchange.getRequestBody().readAllBytes());
        exchange.sendResponseHeaders(201, -1);
    }

    private void delete(HttpExchange exchange, String path) throws IOException {
        boolean removed = files.remove(path) != null | collections.remove(path);
        exchange.sendResponseHeaders(removed ? 204 : 404, -1);
    }

    private void mkcol(HttpExchange exchange, String path) throws IOException {
        String normalised = trimSlash(path);
        if (collections.contains(normalised) || files.containsKey(normalised)) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }
        collections.add(normalised);
        exchange.sendResponseHeaders(201, -1);
    }

    private void move(HttpExchange exchange, String path) throws IOException {
        String destination = exchange.getRequestHeaders().getFirst("Destination");
        if (destination == null) {
            exchange.sendResponseHeaders(400, -1);
            return;
        }
        String target = java.net.URI.create(destination).getPath();
        byte[] content = files.remove(path);
        if (content == null) {
            exchange.sendResponseHeaders(404, -1);
            return;
        }
        files.put(target, content);
        exchange.sendResponseHeaders(201, -1);
    }

    private void copy(HttpExchange exchange) throws IOException {
        String source = exchange.getRequestHeaders().getFirst("Source");
        String destination = exchange.getRequestHeaders().getFirst("Destination");
        if (source == null && destination == null) {
            exchange.sendResponseHeaders(400, -1);
            return;
        }
        String outcome = copyOutcome;
        byte[] body = outcome == null ? new byte[0]
                : ("Perf Marker\nTimestamp: 1\nStripe Index: 0\n"
                        + "Stripe Bytes Transferred: 10\nEnd\n" + outcome + "\n")
                        .getBytes(StandardCharsets.UTF_8);
        send(exchange, 200, body, "text/plain");
    }

    private void propfind(HttpExchange exchange, String path) throws IOException {
        exchange.getRequestBody().readAllBytes();
        String normalised = trimSlash(path);
        boolean isCollection = collections.contains(normalised);
        if (!isCollection && !files.containsKey(normalised)) {
            exchange.sendResponseHeaders(404, -1);
            return;
        }
        String depth = exchange.getRequestHeaders().getFirst("Depth");
        StringBuilder xml = new StringBuilder(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">\n");
        xml.append(entry(normalised, isCollection));
        if ("1".equals(depth) && isCollection) {
            for (Map.Entry<String, byte[]> file : files.entrySet()) {
                if (isChildOf(normalised, file.getKey())) {
                    xml.append(entry(file.getKey(), false));
                }
            }
            for (String child : collections) {
                if (isChildOf(normalised, child)) {
                    xml.append(entry(child, true));
                }
            }
        }
        xml.append("</D:multistatus>\n");
        send(exchange, 207, xml.toString().getBytes(StandardCharsets.UTF_8),
                "application/xml; charset=utf-8");
    }

    private String entry(String path, boolean collection) {
        byte[] content = files.get(path);
        return "<D:response><D:href>" + path + (collection ? "/" : "") + "</D:href>"
                + "<D:propstat><D:prop>"
                + "<D:resourcetype>" + (collection ? "<D:collection/>" : "") + "</D:resourcetype>"
                + "<D:getcontentlength>" + (content == null ? 0 : content.length)
                + "</D:getcontentlength>"
                + "<D:getlastmodified>Tue, 15 Nov 2022 12:45:26 GMT</D:getlastmodified>"
                + "<D:getetag>\"abc123\"</D:getetag>"
                + "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>"
                + "<D:propstat><D:prop><D:quota-used-bytes/></D:prop>"
                + "<D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>"
                + "</D:response>\n";
    }

    private static boolean isChildOf(String parent, String path) {
        String prefix = parent.equals("/") ? "/" : parent + "/";
        return path.startsWith(prefix) && !path.equals(parent)
                && path.indexOf('/', prefix.length()) < 0;
    }

    private static String trimSlash(String path) {
        return path.length() > 1 && path.endsWith("/")
                ? path.substring(0, path.length() - 1) : path;
    }

    private static void send(HttpExchange exchange, int status, byte[] body, String type)
            throws IOException {
        exchange.getResponseHeaders().add("Content-Type", type);
        exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
        if (body.length > 0) {
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }
}

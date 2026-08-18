package io.github.robc.jroot.http;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * A storage element's tape API, as much of one as a test needs.
 *
 * <p>Replies are scripted per path so a test can pin what a real deployment
 * sends — the bodies here are dCache's own field names — and every request is
 * recorded with its body, because half of what this client has to get right
 * is what it sends rather than what it makes of the answer.
 */
public final class MockTapeServer implements AutoCloseable {

    /** One request the client made. */
    public record Call(String method, String path, String body, String authorization) {}

    private final HttpServer server;
    private final Map<String, Reply> replies = new LinkedHashMap<>();
    private final List<Call> calls = new CopyOnWriteArrayList<>();

    private record Reply(int status, String body, String location) {}

    public MockTapeServer() throws IOException {
        server = HttpServer.create(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 8);
        server.createContext("/", this::dispatch);
        server.setExecutor(null);
        server.start();
    }

    public String url(String path) {
        return "http://" + server.getAddress().getAddress().getHostAddress()
                + ":" + server.getAddress().getPort() + path;
    }

    /** Answer {@code path} with this JSON body. */
    public MockTapeServer answering(String path, int status, String body) {
        replies.put(path, new Reply(status, body, null));
        return this;
    }

    /** Answer {@code path} with a status, a body and a {@code Location}. */
    public MockTapeServer answering(String path, int status, String body, String location) {
        replies.put(path, new Reply(status, body, location));
        return this;
    }

    /** The discovery document, naming where the API lives. */
    public MockTapeServer publishing(String root) {
        return answering(TapeApi.WELL_KNOWN, 200,
                "{\"endpoints\":[{\"uri\":\"" + url(root) + "\",\"version\":\"v1\"}]}");
    }

    public List<Call> calls() {
        return List.copyOf(calls);
    }

    public Call call(String method, String path) {
        return calls.stream()
                .filter(call -> call.method().equals(method) && call.path().equals(path))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no " + method + " " + path
                        + " among " + calls));
    }

    private void dispatch(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        try (exchange) {
            calls.add(new Call(exchange.getRequestMethod(), path,
                    new String(exchange.getRequestBody().readAllBytes(),
                            StandardCharsets.UTF_8),
                    exchange.getRequestHeaders().getFirst("Authorization")));
            Reply reply = replies.get(path);
            if (reply == null) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }
            if (reply.location() != null) {
                exchange.getResponseHeaders().add("Location", reply.location());
            }
            byte[] body = reply.body() == null
                    ? new byte[0] : reply.body().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(reply.status(), body.length == 0 ? -1 : body.length);
            if (body.length > 0) {
                exchange.getResponseBody().write(body);
            }
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }
}

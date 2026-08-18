package io.github.robc.jroot.client;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.CRC32C;

import io.github.robc.jroot.wire.WBuf;
import io.github.robc.jroot.wire.XrdConst;

/**
 * An xrootd server, in as much detail as a client test needs: it speaks the
 * real frames, and nothing about it is mocked at the Java level. Tests point
 * a real {@link XrdClient} at a real socket, so a wrong offset or a missing
 * byte fails the test rather than passing through a stub.
 *
 * <p>Behaviour is set per opcode with {@link #on}, which lets one test make
 * the server answer {@code kXR_wait} and another make it redirect, without
 * either knowing how the frames are built.
 *
 * <p>It also binds data paths. A {@code kXR_bind} turns the socket it arrived
 * on into one, after which that socket carries no requests at all: the bulk
 * bytes of a {@code kXR_write} that names it, and the answers to a
 * {@code kXR_read} that does. Splitting the frame is the whole point of the
 * feature, so the server has to put it back together the way a real one does
 * — from {@code dlen} on the control link and the bytes on the path.
 */
final class MockXrootd implements AutoCloseable {

    /**
     * What the server should do with one request. A handler returns every
     * frame the request produces, which is how {@code kXR_oksofar} is
     * expressed: one request, several responses on the same stream.
     */
    interface Handler {
        List<Reply> handle(Request request) throws IOException;
    }

    /** A handler that answers with exactly one frame. */
    static Handler answering(java.util.function.Function<Request, Reply> single) {
        return request -> List.of(single.apply(request));
    }

    record Request(int streamId, int opcode, byte[] params, byte[] payload) {

        String text() {
            return new String(payload, StandardCharsets.UTF_8);
        }

        long offset() {
            long value = 0;
            for (int i = 4; i < 12; i++) {
                value = (value << 8) | (params[i] & 0xFF);
            }
            return value;
        }

        int length() {
            int value = 0;
            for (int i = 12; i < 16; i++) {
                value = (value << 8) | (params[i] & 0xFF);
            }
            return value;
        }

        /** The data path this request named, or 0 for the control link. */
        int pathId() {
            return MockXrootd.pathId(opcode, params, payload);
        }
    }

    /** {@code trailer} is the raw data a {@code kXR_status} frame declares in
     *  its own length and sends after itself, outside the response header. */
    record Reply(int status, byte[] data, byte[] trailer) {

        Reply(int status, byte[] data) {
            this(status, data, new byte[0]);
        }

        static Reply ok(byte[] data) {
            return new Reply(XrdConst.kXR_ok, data);
        }

        /**
         * A {@code kXR_status} answer to {@code requestId}, with its checksum
         * over everything behind it, and {@code trailer} following the frame.
         */
        static Reply status(int requestId, int responseType, byte[] info, byte[] trailer) {
            byte[] body = new WBuf()
                    .u16(0).u8(requestId - XrdConst.kXR_1stRequest).u8(responseType)
                    .zeros(4).i32(trailer.length).raw(info).bytes();
            CRC32C crc = new CRC32C();
            crc.update(body, 0, body.length);
            return new Reply(XrdConst.kXR_status,
                    new WBuf().u32(crc.getValue()).raw(body).bytes(), trailer);
        }

        /** A partial answer: more frames follow on the same stream. */
        static Reply oksofar(byte[] data) {
            return new Reply(XrdConst.kXR_oksofar, data);
        }

        static Reply ok(String text) {
            return ok(text.getBytes(StandardCharsets.UTF_8));
        }

        static Reply error(int code, String message) {
            return new Reply(XrdConst.kXR_error,
                    new WBuf().i32(code).text(message, true).bytes());
        }

        static Reply wait(int seconds, String message) {
            return new Reply(XrdConst.kXR_wait,
                    new WBuf().i32(seconds).text(message, false).bytes());
        }

        static Reply redirect(int port, String host) {
            return new Reply(XrdConst.kXR_redirect,
                    new WBuf().i32(port).text(host, false).bytes());
        }
    }

    private final ServerSocket listener;
    private final Thread acceptor;
    private final Map<Integer, Handler> handlers = new HashMap<>();
    private final List<Request> seen = new CopyOnWriteArrayList<>();
    private final List<Socket> clients = new CopyOnWriteArrayList<>();
    private final Map<Integer, DataPath> paths = new ConcurrentHashMap<>();
    private final AtomicInteger nextPathId = new AtomicInteger(1);
    private volatile int protocolFlags;
    private volatile String securityOffer = "";
    private volatile boolean running = true;

    MockXrootd() throws IOException {
        listener = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
        acceptor = new Thread(this::accept, "mock-xrootd");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    int port() {
        return listener.getLocalPort();
    }

    String url(String path) {
        return "root://" + listener.getInetAddress().getHostAddress() + ":" + port() + "/" + path;
    }

    MockXrootd on(int opcode, Handler handler) {
        handlers.put(opcode, handler);
        return this;
    }

    /** What the {@code kXR_login} reply offers as security protocols. */
    MockXrootd offering(String sec) {
        securityOffer = sec;
        return this;
    }

    /** The extra streams bound to this server, lowest id first. */
    List<Integer> boundPaths() {
        return paths.keySet().stream().sorted().toList();
    }

    List<Request> requests() {
        return List.copyOf(seen);
    }

    List<Integer> opcodes() {
        List<Integer> out = new ArrayList<>();
        seen.forEach(request -> out.add(request.opcode()));
        return out;
    }

    private void accept() {
        while (running) {
            try {
                Socket socket = listener.accept();
                clients.add(socket);
                Thread worker = new Thread(() -> serve(socket), "mock-xrootd-session");
                worker.setDaemon(true);
                worker.start();
            } catch (IOException e) {
                return;                     // the listener closed; nothing left to accept
            }
        }
    }

    private void serve(Socket socket) {
        try {
            socket.setTcpNoDelay(true);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            OutputStream out = socket.getOutputStream();
            handshake(in, out);
            while (running && request(socket, in, out)) {
                // until the client hangs up, or this socket becomes a data path
            }
        } catch (IOException e) {
            // a client that went away mid-session is how close() looks from here
        } catch (RuntimeException e) {
            // A handler that threw would otherwise show up at the client as a
            // closed socket, which says nothing about what actually happened.
            e.printStackTrace();
        } finally {
            // A bound path outlives the thread that bound it: from here on the
            // session's control thread is the one that reads and writes it.
            if (!isBound(socket)) {
                try {
                    socket.close();
                } catch (IOException e) {
                    // already gone
                }
            }
        }
    }

    private boolean isBound(Socket socket) {
        return paths.values().stream().anyMatch(path -> path.socket() == socket);
    }

    private void handshake(DataInputStream in, OutputStream out) throws IOException {
        byte[] hello = new byte[20];
        in.readFully(hello);
        send(out, 0, XrdConst.kXR_ok, new WBuf()
                .i32(XrdConst.kXR_PROTOCOLVERSION).i32(XrdConst.kXR_DataServer).bytes());
    }

    private boolean request(Socket socket, DataInputStream in, OutputStream out)
            throws IOException {
        byte[] header = new byte[XrdConst.REQUEST_HDRLEN];
        try {
            in.readFully(header);
        } catch (IOException e) {
            return false;                   // end of stream: the client hung up
        }
        int streamId = ((header[0] & 0xFF) << 8) | (header[1] & 0xFF);
        int opcode = ((header[2] & 0xFF) << 8) | (header[3] & 0xFF);
        byte[] params = new byte[16];
        System.arraycopy(header, 4, params, 0, 16);
        int dlen = ((header[20] & 0xFF) << 24) | ((header[21] & 0xFF) << 16)
                | ((header[22] & 0xFF) << 8) | (header[23] & 0xFF);
        // dlen counts the bytes on both links; only the ones a data path
        // carries are missing from this socket.
        int onPath = pathDataLength(opcode, params, dlen);
        byte[] payload = new byte[dlen];
        in.readFully(payload, 0, dlen - onPath);
        if (onPath > 0) {
            pathOrFail(params[12] & 0xFF, opcode).in().readFully(payload, dlen - onPath, onPath);
        }
        Request request = new Request(streamId, opcode, params, payload);
        seen.add(request);

        if (opcode == XrdConst.kXR_bind && !handlers.containsKey(XrdConst.kXR_bind)) {
            bind(socket, in, out, streamId);
            return false;               // from here on this socket is a data path
        }
        Handler handler = handlers.get(opcode);
        List<Reply> replies = handler != null ? handler.handle(request) : builtin(request);
        if (replies == null || replies.isEmpty()) {
            replies = List.of(Reply.ok(new byte[0]));
        }
        OutputStream link = replyLink(request, out);
        for (Reply reply : replies) {
            send(link, streamId, reply.status(), reply.data(), reply.trailer());
        }
        return true;
    }

    /**
     * Turn this socket into a data path and name it. Registered before the
     * answer goes out, because the client may put a request down the path as
     * soon as it reads the id.
     */
    private void bind(Socket socket, DataInputStream in, OutputStream out, int streamId)
            throws IOException {
        int pathid = nextPathId.getAndIncrement();
        paths.put(pathid, new DataPath(socket, in, out));
        send(out, streamId, XrdConst.kXR_ok, new byte[] {(byte) pathid});
    }

    /** Which link a request's answer goes down: a read that named a path is
     *  answered on it, and everything else on the link it arrived on. */
    private OutputStream replyLink(Request request, OutputStream control) {
        int pathid = request.pathId();
        if (pathid == 0 || request.opcode() == XrdConst.kXR_write
                || request.opcode() == XrdConst.kXR_pgwrite) {
            return control;
        }
        return pathOrFail(pathid, request.opcode()).out();
    }

    /** How many of a request's {@code dlen} bytes travel down a data path
     *  rather than the control link. */
    private static int pathDataLength(int opcode, byte[] params, int dlen) {
        return (opcode == XrdConst.kXR_write || opcode == XrdConst.kXR_pgwrite)
                && (params[12] & 0xFF) != 0 ? dlen : 0;
    }

    /** The path id a request names. Where the byte sits is per-opcode: the
     *  parameters for a write, an optional payload for a read. */
    private static int pathId(int opcode, byte[] params, byte[] payload) {
        return switch (opcode) {
            case XrdConst.kXR_write, XrdConst.kXR_pgwrite -> params[12] & 0xFF;
            case XrdConst.kXR_readv -> params[15] & 0xFF;
            case XrdConst.kXR_read -> payload.length >= 1 ? payload[0] & 0xFF : 0;
            default -> 0;
        };
    }

    private DataPath pathOrFail(int pathid, int opcode) {
        DataPath path = paths.get(pathid);
        if (path == null) {
            throw new IllegalStateException("opcode " + opcode + " named data path "
                    + pathid + ", which is not bound");
        }
        return path;
    }

    /** One bound socket, and the streams the session's control thread uses to
     *  work it. */
    private record DataPath(Socket socket, DataInputStream in, OutputStream out) {}

    /** The bring-up requests every session makes, answered the same way each time. */
    private List<Reply> builtin(Request request) {
        return switch (request.opcode()) {
            case XrdConst.kXR_protocol -> List.of(Reply.ok(new WBuf()
                    .i32(XrdConst.kXR_PROTOCOLVERSION).i32(protocolFlags).bytes()));
            case XrdConst.kXR_login -> List.of(Reply.ok(new WBuf()
                    .zeros(XrdConst.SESSION_ID_LEN)
                    .text(securityOffer, false).bytes()));
            default -> List.of(Reply.ok(new byte[0]));
        };
    }

    private void send(OutputStream out, int streamId, int status, byte[] data)
            throws IOException {
        send(out, streamId, status, data, new byte[0]);
    }

    private void send(OutputStream out, int streamId, int status, byte[] data, byte[] trailer)
            throws IOException {
        synchronized (out) {
            out.write(new WBuf().u16(streamId).u16(status).i32(data.length)
                    .raw(data).raw(trailer).bytes());
            out.flush();
        }
    }

    /**
     * Close every session this server is holding, without stopping it. What
     * a client sees is what a restarted daemon, a dropped route or a
     * firewall with an idle timeout looks like: the socket ends mid-session
     * and the next connection is accepted as if nothing had happened.
     */
    void dropConnections() {
        for (Socket client : clients) {
            try {
                client.close();
            } catch (IOException e) {
                // already gone
            }
        }
        clients.clear();
        paths.clear();
    }

    /** Send an unsolicited response on {@code streamId}, as a server does when
     *  it answers a {@code kXR_waitresp} later. */
    void push(int streamId, int status, byte[] data) throws IOException {
        for (Socket client : clients) {
            if (!client.isClosed()) {
                send(client.getOutputStream(), streamId, status, data);
            }
        }
    }

    static byte[] statLine(String id, long size, int flags, long mtime) {
        return (id + " " + size + " " + flags + " " + mtime).getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public void close() throws IOException {
        running = false;
        listener.close();
        for (Socket client : clients) {
            try {
                client.close();
            } catch (IOException e) {
                // already gone
            }
        }
        acceptor.interrupt();
    }

    /** Read every byte of a stream, for handlers that echo a payload back. */
    static byte[] drain(InputStream in) throws IOException {
        return in.readAllBytes();
    }
}

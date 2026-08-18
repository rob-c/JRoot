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
import java.util.concurrent.CopyOnWriteArrayList;

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
    }

    record Reply(int status, byte[] data) {

        static Reply ok(byte[] data) {
            return new Reply(XrdConst.kXR_ok, data);
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
        try (socket) {
            socket.setTcpNoDelay(true);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            OutputStream out = socket.getOutputStream();
            handshake(in, out);
            while (running) {
                if (!request(in, out)) {
                    return;
                }
            }
        } catch (IOException e) {
            // a client that went away mid-session is how close() looks from here
        }
    }

    private void handshake(DataInputStream in, OutputStream out) throws IOException {
        byte[] hello = new byte[20];
        in.readFully(hello);
        send(out, 0, XrdConst.kXR_ok, new WBuf()
                .i32(XrdConst.kXR_PROTOCOLVERSION).i32(XrdConst.kXR_DataServer).bytes());
    }

    private boolean request(DataInputStream in, OutputStream out) throws IOException {
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
        byte[] payload = new byte[dlen];
        in.readFully(payload);
        Request request = new Request(streamId, opcode, params, payload);
        seen.add(request);

        Handler handler = handlers.get(opcode);
        List<Reply> replies = handler != null ? handler.handle(request) : builtin(request);
        if (replies == null || replies.isEmpty()) {
            replies = List.of(Reply.ok(new byte[0]));
        }
        for (Reply reply : replies) {
            send(out, streamId, reply.status(), reply.data());
        }
        return true;
    }

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
        out.write(new WBuf().u16(streamId).u16(status).i32(data.length).raw(data).bytes());
        out.flush();
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

package io.github.robc.jroot.client;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.zip.CRC32C;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdAuthException;
import io.github.robc.jroot.XrdConnectionException;
import io.github.robc.jroot.XrdException;
import io.github.robc.jroot.XrdProtocolException;
import io.github.robc.jroot.XrdServerException;
import io.github.robc.jroot.auth.Credential;
import io.github.robc.jroot.auth.CredentialLadder;
import io.github.robc.jroot.auth.SecurityOffer;
import io.github.robc.jroot.crypto.Signer;
import io.github.robc.jroot.wire.RBuf;
import io.github.robc.jroot.wire.Requests;
import io.github.robc.jroot.wire.ResponseHeader;
import io.github.robc.jroot.wire.Responses;
import io.github.robc.jroot.wire.Types.LoginInfo;
import io.github.robc.jroot.wire.Types.ProtocolInfo;
import io.github.robc.jroot.wire.Types.RedirectInfo;
import io.github.robc.jroot.wire.Types.StatusInfo;
import io.github.robc.jroot.wire.Types.WaitInfo;
import io.github.robc.jroot.wire.XrdConst;
import io.github.robc.jroot.wire.XrdRequest;

/**
 * One TCP connection to one xrootd server, from the handshake to the last
 * response.
 *
 * <p>Bring-up runs on the calling thread — handshake and {@code kXR_protocol}
 * pipelined, the TLS upgrade if the server demands one, {@code kXR_login},
 * then the authentication ladder — because until it is finished the socket
 * itself can be replaced under the client, and a reader thread racing that
 * swap would read half a TLS record as protocol. Once the session is up a
 * daemon reader thread owns the socket and requests are multiplexed by
 * stream id, each one a {@link CompletableFuture} the caller waits on.
 *
 * <p>Instances are safe to share between threads: writes are serialised so
 * that a {@code kXR_sigver} frame and the request it signs stay adjacent and
 * in sequence-number order, which is the one ordering the protocol cares
 * about.
 */
public final class XrdConnection implements Closeable {

    /** Stream ids 0-3 belong to bring-up; regular traffic starts above them.
     *  A data path's own bring-up reuses them: it is the same conversation,
     *  on a socket that has no traffic of its own yet. */
    private static final int HANDSHAKE_SID = 0;
    private static final int PROTOCOL_SID = 1;
    private static final int LOGIN_SID = 2;
    private static final int BIND_SID = LOGIN_SID;
    private static final int AUTH_SID = 3;
    private static final int FIRST_SID = 4;
    private static final int MAX_SID = 0xFFFF;

    /** A ceiling on what one response may accumulate across {@code kXR_oksofar}
     *  frames, so a server that never says "done" cannot exhaust the heap. */
    private static final long MAX_ACCUMULATED = 1L << 30;

    private static final byte[] EMPTY = new byte[0];

    private final XrdUrl url;
    private final Config config;
    private final Map<Integer, Stream> streams = new ConcurrentHashMap<>();
    private final Map<Integer, DataPath> paths = new ConcurrentHashMap<>();
    private final Object writeLock = new Object();
    private final Object bindLock = new Object();

    private Socket socket;
    private InputStream in;
    private OutputStream out;
    private Thread reader;

    private volatile boolean closed;
    private volatile XrdException failure;
    private int nextSid = FIRST_SID;

    private ProtocolInfo protocol = ProtocolInfo.NONE;
    private LoginInfo login;
    private Signer signer;
    private String mechanism = "";
    private boolean tls;
    private int serverType;
    private boolean pathsBound;
    private volatile String pathRefusal = "";

    private XrdConnection(XrdUrl url, Config config) {
        this.url = url;
        this.config = config;
    }

    /** Connect, negotiate, log in and authenticate. */
    public static XrdConnection open(XrdUrl url, Config config) {
        XrdConnection connection = new XrdConnection(url, config);
        try {
            connection.bringUp();
        } catch (RuntimeException e) {
            connection.closeQuietly();
            throw e;
        }
        return connection;
    }

    public XrdUrl url() {
        return url;
    }

    public ProtocolInfo protocol() {
        return protocol;
    }

    public LoginInfo login() {
        return login;
    }

    /** The mechanism that authenticated this session, {@code ""} if none was
     *  needed. */
    public String mechanism() {
        return mechanism;
    }

    public boolean isTls() {
        return tls;
    }

    /** {@code kXR_DataServer} or {@code kXR_LBalServer}, from the handshake. */
    public int serverType() {
        return serverType;
    }

    public boolean isDataServer() {
        return serverType == XrdConst.kXR_DataServer;
    }

    public boolean isOpen() {
        return !closed && failure == null;
    }

    // -----------------------------------------------------------------
    // Bring-up
    // -----------------------------------------------------------------

    private void bringUp() {
        connectSocket();
        handshake();
        if (wantsTls()) {
            upgradeToTls();
        }
        authenticate(doLogin());
        startReader();
    }

    private void connectSocket() {
        socket = connect();
        try {
            in = socket.getInputStream();
            out = socket.getOutputStream();
        } catch (IOException e) {
            throw new XrdConnectionException(
                    "cannot connect to " + url.host() + ":" + url.port() + ": " + e.getMessage(), e);
        }
    }

    private Socket connect() {
        try {
            Socket plain = new Socket();
            plain.setTcpNoDelay(true);
            plain.connect(new InetSocketAddress(url.host(), url.port()),
                    (int) config.connectTimeout().toMillis());
            return plain;
        } catch (IOException e) {
            throw new XrdConnectionException(
                    "cannot connect to " + url.host() + ":" + url.port() + ": " + e.getMessage(), e);
        }
    }

    /** The handshake and {@code kXR_protocol}, pipelined into one write. */
    private void handshake() {
        int flags = XrdConst.kXR_secreqs | XrdConst.kXR_ableTLS;
        if (config.tls() == Config.Tls.REQUIRED || url.requiresTls()) {
            flags |= XrdConst.kXR_wantTLS;
        }
        write(concat(XrdRequest.HANDSHAKE, new Requests.Protocol(flags).encode(PROTOCOL_SID)));

        ServerResponse hello = readSync(HANDSHAKE_SID, null);
        RBuf r = new RBuf(hello.data(), "ServerInitHandShake");
        r.i32();                                   // protocol version, superseded
        serverType = r.i32();
        protocol = Responses.parseProtocol(readSync(PROTOCOL_SID, null).data());
    }

    private boolean wantsTls() {
        return switch (config.tls()) {
            case DISABLED -> {
                if (protocol.demandsTls() || url.requiresTls()) {
                    throw new XrdConnectionException(url.host()
                            + " requires TLS and this client was configured without it");
                }
                yield false;
            }
            case REQUIRED -> true;
            case AUTO -> protocol.demandsTls() || url.requiresTls();
        };
    }

    private void upgradeToTls() {
        if (!protocol.hasTls()) {
            throw new XrdConnectionException(url.host() + " does not offer TLS");
        }
        SSLSocket ssl = wrapInTls(socket);
        socket = ssl;
        try {
            in = ssl.getInputStream();
            out = ssl.getOutputStream();
        } catch (IOException e) {
            throw new XrdConnectionException(
                    "TLS with " + url.host() + " left no usable stream: " + e.getMessage(), e);
        }
        tls = true;
    }

    /** Put an already-connected socket inside TLS, in place, as the protocol's
     *  in-band upgrade does. */
    private SSLSocket wrapInTls(Socket plain) {
        try {
            SSLSocket ssl = (SSLSocket) TlsFactory.create(config).getSocketFactory()
                    .createSocket(plain, url.host(), url.port(), true);
            ssl.setUseClientMode(true);
            SSLParameters parameters = ssl.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm(config.verifyPeer() ? "HTTPS" : null);
            ssl.setSSLParameters(parameters);
            ssl.startHandshake();
            return ssl;
        } catch (IOException e) {
            throw new XrdConnectionException(
                    "TLS handshake with " + url.host() + " failed: " + e.getMessage(), e);
        }
    }

    private List<SecurityOffer> doLogin() {
        String username = !url.user().isEmpty() ? url.user() : config.username();
        int pid = (int) ProcessHandle.current().pid();
        ServerResponse response = request(LOGIN_SID, new Requests.Login(username, pid, ""), config.requestTimeout());
        login = Responses.parseLogin(response.data());
        return SecurityOffer.parse(login.sec());
    }

    private void authenticate(List<SecurityOffer> offers) {
        if (offers.isEmpty()) {
            return;                                 // the server wants nobody named
        }
        CredentialLadder ladder = CredentialLadder.build(offers, config);
        if (ladder.isEmpty()) {
            throw new XrdAuthException(url.host() + " offered "
                    + offers.stream().map(SecurityOffer::name).toList()
                    + " and none could be used — " + ladder.explain());
        }
        Map<String, String> failures = new LinkedHashMap<>(ladder.rejections());
        for (CredentialLadder.Candidate candidate : ladder.candidates()) {
            try {
                runExchange(candidate.credential());
                mechanism = candidate.credential().name();
                installSigner(candidate.credential());
                return;
            } catch (XrdServerException | XrdAuthException | XrdProtocolException e) {
                failures.put(candidate.credential().name(), e.getMessage());
            }
        }
        throw new XrdAuthException("no mechanism authenticated to " + url.host() + " — "
                + failures.entrySet().stream()
                        .map(entry -> entry.getKey() + ": " + entry.getValue())
                        .reduce((a, b) -> a + "; " + b).orElse(""));
    }

    private void runExchange(Credential credential) {
        byte[] blob = credential.initial();
        for (int round = 0; round < 32; round++) {
            ServerResponse response =
                    request(AUTH_SID, new Requests.Auth(credential.name(), blob),
                            config.requestTimeout());
            if (response.status() != XrdConst.kXR_authmore) {
                return;
            }
            blob = credential.step(response.data());
            if (blob == null) {
                throw new XrdAuthException(credential.name()
                        + " has nothing more to send but the server asked again");
            }
        }
        throw new XrdAuthException(credential.name() + " did not converge in 32 rounds");
    }

    private void installSigner(Credential credential) {
        byte[] key = credential.sessionKey();
        if (key == null || key.length == 0
                || protocol.securityLevel() <= XrdConst.kXR_secCompatible
                        && protocol.securityOverrides().isEmpty()) {
            return;
        }
        signer = new Signer(key, credential.sessionCipher(), protocol.securityLevel(),
                protocol.securityOverrides(),
                (protocol.securityOptions() & XrdConst.kXR_secOData) != 0, false);
    }

    // -----------------------------------------------------------------
    // Requests
    // -----------------------------------------------------------------

    /**
     * Send a request and wait for its answer, sitting out any
     * {@code kXR_wait} the server asks for. Never returns
     * {@code kXR_wait}: an error arrives as {@link XrdServerException} and
     * a redirect as {@link XrdRedirectException}.
     */
    public ServerResponse request(XrdRequest request) {
        return request(-1, request, config.requestTimeout());
    }

    /**
     * The same, for a request the server is expected to sit on far longer
     * than an ordinary one — the second {@code kXR_sync} of a third-party
     * copy does not answer until the whole transfer has finished.
     */
    public ServerResponse request(XrdRequest request, Duration timeout) {
        return request(-1, request, timeout);
    }

    private ServerResponse request(int fixedSid, XrdRequest request, Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (true) {
            ServerResponse response = fixedSid >= 0
                    ? sendSync(fixedSid, request)
                    : sendMultiplexed(request, timeout);
            if (response.status() != XrdConst.kXR_wait) {
                return response;
            }
            WaitInfo wait = Responses.parseWait(response.data());
            long left = TimeUnit.NANOSECONDS.toSeconds(deadline - System.nanoTime());
            if (wait.seconds() > config.maxWaitSeconds() || wait.seconds() > left) {
                throw new XrdServerException(XrdConst.kXR_ServerError,
                        url.host() + " asked for " + wait.seconds() + "s of patience"
                                + (wait.message().isEmpty() ? "" : " (" + wait.message() + ")")
                                + ", more than is left of this request's time");
            }
            sleep(wait.seconds());
        }
    }

    /** Bring-up path: no reader thread yet, so the answer is read here. */
    private ServerResponse sendSync(int sid, XrdRequest request) {
        transmit(sid, request);
        return readSync(sid, request);
    }

    private ServerResponse sendMultiplexed(XrdRequest request, Duration timeout) {
        Stream stream = newStream();
        try {
            transmit(stream.id, request);
            return await(stream, timeout);
        } finally {
            streams.remove(stream.id);
        }
    }

    private ServerResponse await(Stream stream, Duration timeout) {
        try {
            return stream.future.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            throw new XrdConnectionException(url.host() + " did not answer within " + timeout);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new XrdConnectionException("interrupted waiting for " + url.host(), e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof XrdException xrd) {
                throw xrd;
            }
            throw new XrdConnectionException("request to " + url.host() + " failed: "
                    + cause.getMessage(), cause);
        }
    }

    /**
     * Put a request on the wire.
     *
     * <p>A request naming a bound data path is split: the header goes out on
     * the control link and the bulk bytes down the path, which is what the
     * server expects when it reads {@code dlen} from a header that arrived
     * on one socket and the data from another. The path's lock is taken
     * first and held across both writes, because the server pairs the
     * <em>n</em>th header naming a path with the <em>n</em>th block of bytes
     * on it; the control link is locked only for the header, so requests on
     * different paths stream their data at the same time, which is the whole
     * point of having them. The order is always path then control, and a
     * request without a path takes only the control lock, so the two can
     * never deadlock.
     *
     * <p>Signing happens here rather than at the call site so that a
     * signature, its sequence number and the request it covers cannot be
     * interleaved with another thread's.
     */
    private void transmit(int sid, XrdRequest request) {
        DataPath path = pathFor(request);
        if (path == null) {
            synchronized (writeLock) {
                writeTo(out, signature(sid, request), request.encode(sid));
            }
            return;
        }
        synchronized (path.writeLock) {
            synchronized (writeLock) {
                writeTo(out, signature(sid, request), request.controlFrame(sid));
            }
            writeTo(path.out, EMPTY, request.pathData());
        }
    }

    /**
     * The {@code kXR_sigver} frame that must precede {@code request}, or no
     * bytes when the security level does not call for one. The signature
     * covers the request as one contiguous frame even when it is about to be
     * split across two sockets: {@code dlen} counts the same bytes either way.
     */
    private byte[] signature(int sid, XrdRequest request) {
        if (signer == null) {
            return EMPTY;
        }
        Signer.Signature signature = signer.sign(request.encode(sid));
        if (signature == null) {
            return EMPTY;
        }
        return new Requests.Sigver(request.opcode(), signature.sequence(),
                signature.bytes(), signature.nodata()).encode(sid);
    }

    private void write(byte[] frame) {
        synchronized (writeLock) {
            writeTo(out, EMPTY, frame);
        }
    }

    private void writeTo(OutputStream sink, byte[] first, byte[] second) {
        try {
            if (first.length > 0) {
                sink.write(first);
            }
            sink.write(second);
            sink.flush();
        } catch (IOException e) {
            throw fail(new XrdConnectionException(
                    "writing to " + url.host() + " failed: " + e.getMessage(), e));
        }
    }

    private synchronized Stream newStream() {
        if (!isOpen()) {
            throw failure != null ? failure
                    : new XrdConnectionException("the connection to " + url.host() + " is closed");
        }
        for (int tried = 0; tried <= MAX_SID - FIRST_SID; tried++) {
            int id = nextSid;
            nextSid = nextSid >= MAX_SID ? FIRST_SID : nextSid + 1;
            if (!streams.containsKey(id)) {
                Stream stream = new Stream(id);
                streams.put(id, stream);
                return stream;
            }
        }
        throw new XrdConnectionException("all 65532 stream ids to " + url.host() + " are in use");
    }

    // -----------------------------------------------------------------
    // Data paths
    // -----------------------------------------------------------------

    /**
     * One extra TCP stream bound to this session.
     *
     * <p>It carries no session of its own: the {@code kXR_bind} that created
     * it named the control link's session id, so the server treats the two
     * sockets as one client. Responses on it carry the control link's stream
     * ids and land in the same table, which is why a caller cannot tell
     * which socket answered — and does not need to.
     */
    private static final class DataPath {
        private final int pathid;
        private final Socket socket;
        private final InputStream in;
        private final OutputStream out;
        private final Object writeLock = new Object();

        DataPath(int pathid, Socket socket, InputStream in, OutputStream out) {
            this.pathid = pathid;
            this.socket = socket;
            this.in = in;
            this.out = out;
        }
    }

    /** The data paths bound to this session, lowest id first. Empty when the
     *  session runs on the control link alone. */
    public int[] dataPaths() {
        return paths.keySet().stream().mapToInt(Integer::intValue).sorted().toArray();
    }

    /** Why binding stopped short of what the configuration asked for, or
     *  {@code ""} when it did not. */
    public String pathRefusal() {
        return pathRefusal;
    }

    /**
     * Bring this session up to {@link Config#dataStreams()} TCP streams,
     * once. Called when a file is opened rather than at login, so a session
     * that only ever stats a path never pays for sockets it will not use.
     *
     * <p>An extra stream is an optimisation, not a requirement: a server that
     * refuses to bind one leaves the session working on the control link, and
     * says so through {@link #pathRefusal()}.
     */
    public void ensureDataPaths() {
        if (pathsBound || config.dataStreams() <= 1) {
            return;
        }
        synchronized (bindLock) {
            if (pathsBound) {
                return;
            }
            pathsBound = true;
            for (int stream = 1; stream < config.dataStreams(); stream++) {
                if (!bindDataPath()) {
                    return;
                }
            }
        }
    }

    /**
     * A second socket to the same server, brought up to the point where the
     * session owns it: handshake and {@code kXR_protocol} as the control link
     * ran them, the same TLS the control link is inside, then
     * {@code kXR_bind} naming the session id. There is no login and no
     * authentication — the session id is the credential.
     */
    private boolean bindDataPath() {
        if (login == null || !isOpen()) {
            return false;
        }
        Socket bound = null;
        try {
            bound = connect();
            InputStream bin = bound.getInputStream();
            OutputStream bout = bound.getOutputStream();

            int flags = XrdConst.kXR_secreqs | XrdConst.kXR_ableTLS
                    | (tls ? XrdConst.kXR_wantTLS : 0);
            writeTo(bout, XrdRequest.HANDSHAKE,
                    new Requests.Protocol(flags).encode(PROTOCOL_SID));
            readBindFrame(bin, HANDSHAKE_SID);                  // ServerInitHandShake
            ProtocolInfo answer = Responses.parseProtocol(readBindFrame(bin, PROTOCOL_SID));
            if (tls || answer.demandsTls()) {
                SSLSocket ssl = wrapInTls(bound);
                bound = ssl;
                bin = ssl.getInputStream();
                bout = ssl.getOutputStream();
            }

            writeTo(bout, EMPTY, new Requests.Bind(login.sessionId()).encode(BIND_SID));
            int pathid = Responses.parseBind(readBindFrame(bin, BIND_SID));
            if (paths.containsKey(pathid)) {
                throw new XrdProtocolException(url.host() + " bound path id " + pathid
                        + " twice; one of the two would take the other's data");
            }
            DataPath path = new DataPath(pathid, bound, bin, bout);
            // Registered before its reader starts: a request may name the path
            // as soon as this returns, and the reader only ever reads.
            paths.put(pathid, path);
            daemon(() -> readLoop(path.in, "data path " + pathid),
                    "jroot-" + url.host() + ":" + url.port() + "-path" + pathid);
            return true;
        } catch (IOException | XrdException e) {
            pathRefusal = e.getMessage();
            closeQuietly(bound);
            return false;
        }
    }

    /** A data path's bring-up reads, before anything is multiplexed on it. */
    private byte[] readBindFrame(InputStream source, int sid) throws IOException {
        while (true) {
            ResponseHeader header = ResponseHeader.decode(
                    readFully(source, XrdConst.RESPONSE_HDRLEN));
            byte[] body = readFully(source, header.dataLength());
            if (header.status() == XrdConst.kXR_attn) {
                continue;                           // advisory: nothing is in flight yet
            }
            if (header.streamId() != sid) {
                throw new XrdProtocolException(url.host() + " answered stream "
                        + header.streamId() + " while binding a data path");
            }
            switch (header.status()) {
                case XrdConst.kXR_ok -> {
                    return body;
                }
                case XrdConst.kXR_error -> {
                    Responses.ErrorInfo error = Responses.parseError(body);
                    throw new XrdServerException(error.code(), error.message());
                }
                default -> throw new XrdProtocolException("unexpected "
                        + XrdConst.statusName(header.status()) + " while binding a data path to "
                        + url.host());
            }
        }
    }

    /** The path a request names, or {@code null} for the control link. */
    private DataPath pathFor(XrdRequest request) {
        int pathid = request.pathId();
        if (pathid == 0) {
            return null;
        }
        DataPath path = paths.get(pathid);
        if (path == null) {
            // Not an assertion failure: a caller can hold an id from before a
            // redirect replaced the session that bound it.
            throw new XrdConnectionException("no data path " + pathid
                    + " is bound to the session with " + url.host());
        }
        return path;
    }

    // -----------------------------------------------------------------
    // Reading
    // -----------------------------------------------------------------

    private void startReader() {
        reader = daemon(() -> readLoop(in, "connection"),
                "jroot-" + url.host() + ":" + url.port());
    }

    private static Thread daemon(Runnable body, String name) {
        Thread thread = new Thread(body, name);
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    private void readLoop(InputStream source, String what) {
        try {
            while (!closed) {
                ResponseHeader header =
                        ResponseHeader.decode(readFully(source, XrdConst.RESPONSE_HDRLEN));
                dispatch(source, header, readFully(source, header.dataLength()));
            }
        } catch (IOException e) {
            if (!closed) {
                fail(new XrdConnectionException("the " + what + " to " + url.host()
                        + " ended: " + e.getMessage(), e));
            }
        } catch (XrdException e) {
            fail(e);
        } finally {
            closeQuietly();
        }
    }

    private void dispatch(InputStream source, ResponseHeader header, byte[] body)
            throws IOException {
        if (header.status() == XrdConst.kXR_attn) {
            attention(source, body);
            return;
        }
        Stream stream = streams.get(header.streamId());
        if (stream == null) {
            // A late answer to a request nobody is waiting for any more:
            // the bytes are already consumed, which is all that matters.
            return;
        }
        switch (header.status()) {
            case XrdConst.kXR_ok, XrdConst.kXR_authmore -> {
                stream.accumulate(body);
                stream.future.complete(new ServerResponse(header.status(), stream.take(), null));
            }
            case XrdConst.kXR_oksofar -> stream.accumulate(body);
            case XrdConst.kXR_wait -> stream.future.complete(
                    new ServerResponse(XrdConst.kXR_wait, body, null));
            case XrdConst.kXR_waitresp -> {
                // The answer itself arrives later on this same stream; the
                // only thing to do is keep waiting for it.
            }
            case XrdConst.kXR_error -> {
                Responses.ErrorInfo error = Responses.parseError(body);
                stream.future.completeExceptionally(
                        new XrdServerException(error.code(), error.message()));
            }
            case XrdConst.kXR_redirect -> stream.future.completeExceptionally(
                    new XrdRedirectException(Responses.parseRedirect(body)));
            case XrdConst.kXR_status -> status(source, stream, body);
            default -> stream.future.completeExceptionally(new XrdProtocolException(
                    "unknown response status " + header.status() + " from " + url.host()));
        }
    }

    /**
     * A {@code kXR_status} response: a CRC-protected header whose own
     * {@code dlen} counts raw data travelling <em>after</em> the frame,
     * outside the response header's length.
     */
    private void status(InputStream source, Stream stream, byte[] body) throws IOException {
        StatusInfo info = Responses.parseStatus(body);
        verifyStatusCrc(body, info);
        byte[] data = readFully(source, info.dataLength());
        stream.accumulate(data);
        if (stream.status == null) {
            stream.status = info;
        }
        if (info.isFinal()) {
            stream.future.complete(
                    new ServerResponse(XrdConst.kXR_status, stream.take(), stream.status));
        }
    }

    /** The checksum covers every byte of the status body after itself. */
    private void verifyStatusCrc(byte[] body, StatusInfo info) {
        CRC32C crc = new CRC32C();
        crc.update(body, 4, body.length - 4);
        if (crc.getValue() != info.crc32c()) {
            throw new XrdProtocolException(String.format(
                    "kXR_status from %s is corrupt: computed %08x, server sent %08x",
                    url.host(), crc.getValue(), info.crc32c()));
        }
    }

    /**
     * {@code kXR_attn}. The one action that matters to a client is
     * {@code kXR_asynresp}, which carries a complete response for a request
     * still in flight; everything else is advisory and dropped.
     */
    private void attention(InputStream source, byte[] body) throws IOException {
        RBuf r = new RBuf(body, "kXR_attn");
        int action = r.i32();
        if (action != XrdConst.kXR_asynresp) {
            return;
        }
        r.skip(4);                                  // reserved
        byte[] embedded = r.rest();
        ResponseHeader header = ResponseHeader.decode(embedded);
        byte[] payload = new byte[Math.min(header.dataLength(),
                Math.max(embedded.length - XrdConst.RESPONSE_HDRLEN, 0))];
        System.arraycopy(embedded, XrdConst.RESPONSE_HDRLEN, payload, 0, payload.length);
        dispatch(source, header, payload);
    }

    /** Bring-up reads: the reader thread is not running yet. */
    private ServerResponse readSync(int sid, XrdRequest request) {
        ByteArrayOutputStream accumulated = new ByteArrayOutputStream();
        long deadline = System.nanoTime() + config.requestTimeout().toNanos();
        try {
            while (true) {
                ResponseHeader header =
                        ResponseHeader.decode(readFully(in, XrdConst.RESPONSE_HDRLEN));
                byte[] body = readFully(in, header.dataLength());
                if (header.streamId() != sid) {
                    if (header.status() == XrdConst.kXR_attn) {
                        continue;               // advisory: nothing is in flight yet
                    }
                    throw new XrdProtocolException(url.host() + " answered stream "
                            + header.streamId() + " during bring-up of stream " + sid);
                }
                switch (header.status()) {
                    case XrdConst.kXR_ok, XrdConst.kXR_authmore -> {
                        accumulated.writeBytes(body);
                        return new ServerResponse(header.status(), accumulated.toByteArray(), null);
                    }
                    case XrdConst.kXR_oksofar -> accumulated.writeBytes(body);
                    case XrdConst.kXR_waitresp -> { }
                    case XrdConst.kXR_wait -> {
                        if (request == null) {
                            throw new XrdProtocolException(
                                    url.host() + " asked the handshake to wait");
                        }
                        WaitInfo wait = Responses.parseWait(body);
                        long left = TimeUnit.NANOSECONDS.toSeconds(deadline - System.nanoTime());
                        if (wait.seconds() > config.maxWaitSeconds() || wait.seconds() > left) {
                            throw new XrdServerException(XrdConst.kXR_ServerError, url.host()
                                    + " asked for " + wait.seconds() + "s before logging in");
                        }
                        sleep(wait.seconds());
                        transmit(sid, request);
                    }
                    case XrdConst.kXR_error -> {
                        Responses.ErrorInfo error = Responses.parseError(body);
                        throw new XrdServerException(error.code(), error.message());
                    }
                    case XrdConst.kXR_redirect ->
                            throw new XrdRedirectException(Responses.parseRedirect(body));
                    default -> throw new XrdProtocolException("unexpected "
                            + XrdConst.statusName(header.status()) + " during bring-up with "
                            + url.host());
                }
            }
        } catch (IOException e) {
            throw new XrdConnectionException(
                    "reading from " + url.host() + " failed: " + e.getMessage(), e);
        }
    }

    private byte[] readFully(InputStream source, int length) throws IOException {
        byte[] out = new byte[length];
        int read = 0;
        while (read < length) {
            int n = source.read(out, read, length - read);
            if (n < 0) {
                throw new EOFException(url.host() + " closed the connection");
            }
            read += n;
        }
        return out;
    }

    // -----------------------------------------------------------------
    // Teardown
    // -----------------------------------------------------------------

    @Override
    public void close() {
        if (closed) {
            return;
        }
        if (login != null && isOpen()) {
            try {
                request(new Requests.EndSession(login.sessionId()));
            } catch (RuntimeException e) {
                // A polite goodbye the server did not want to hear changes
                // nothing: the socket is about to go.
            }
        }
        closeQuietly();
    }

    private void closeQuietly() {
        closed = true;
        closeQuietly(socket);
        for (DataPath path : paths.values()) {
            closeQuietly(path.socket);
        }
        paths.clear();
        XrdException reason = failure != null ? failure
                : new XrdConnectionException("the connection to " + url.host() + " was closed");
        for (Stream stream : streams.values()) {
            stream.future.completeExceptionally(reason);
        }
        streams.clear();
    }

    private static void closeQuietly(Socket doomed) {
        try {
            if (doomed != null) {
                doomed.close();
            }
        } catch (IOException e) {
            // Closing a socket that is already gone is not news.
        }
    }

    private XrdException fail(XrdException reason) {
        if (failure == null) {
            failure = reason;
        }
        return reason;
    }

    private static void sleep(int seconds) {
        try {
            Thread.sleep(seconds * 1000L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new XrdConnectionException("interrupted while waiting out a kXR_wait", e);
        }
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] out = new byte[first.length + second.length];
        System.arraycopy(first, 0, out, 0, first.length);
        System.arraycopy(second, 0, out, first.length, second.length);
        return out;
    }

    @Override
    public String toString() {
        int extra = paths.size();
        return "XrdConnection[" + url.serverKey() + (tls ? ", tls" : "")
                + (mechanism.isEmpty() ? "" : ", " + mechanism)
                + (extra == 0 ? "" : ", " + (extra + 1) + " streams") + "]";
    }

    /** One in-flight request. */
    private static final class Stream {
        private final int id;
        private final CompletableFuture<ServerResponse> future = new CompletableFuture<>();
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private StatusInfo status;

        Stream(int id) {
            this.id = id;
        }

        void accumulate(byte[] data) {
            if (buffer.size() + (long) data.length > MAX_ACCUMULATED) {
                throw new XrdProtocolException("a single response grew past "
                        + MAX_ACCUMULATED + " bytes without ending");
            }
            buffer.writeBytes(data);
        }

        byte[] take() {
            return buffer.toByteArray();
        }
    }

    /** Where a redirect points, for a caller that follows one. */
    public static RedirectInfo redirectOf(XrdRedirectException e) {
        return e.redirect();
    }
}

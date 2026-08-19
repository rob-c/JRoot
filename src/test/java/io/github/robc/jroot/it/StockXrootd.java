package io.github.robc.jroot.it;

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * The official {@code xrootd}, running on this machine with a throwaway PKI,
 * bound to GSI and nothing else.
 *
 * <p>Every other server in these tests is one we wrote, which makes them
 * excellent at catching our own mistakes and useless at catching a
 * disagreement about what the protocol says: a client and a server built from
 * the same reading of the spec agree with each other whether or not the
 * reading is right. This one is the upstream C++ implementation, provisioned
 * by {@code src/test/resources/it/xrootd-gsi-server.sh}, so the only piece of
 * JRoot in the exchange is the client under test.
 *
 * <p>It is skipped when the official tools are not installed — see
 * {@link #available()} — and only then. If the tools are there and the server
 * will not start, the tests fail: a silent skip on a machine that can run this
 * is how an interop test quietly stops testing anything.
 */
final class StockXrootd implements AutoCloseable {

    private static final Path SCRIPT =
            Path.of("src", "test", "resources", "it", "xrootd-gsi-server.sh");
    private static final Path OPENSSL = Path.of("/usr/bin/openssl");
    private static final String[] BINARIES = {"xrootd", "xrdgsiproxy", "ss"};

    private final Path base;
    private final Map<String, String> reported;

    private StockXrootd(Path base, Map<String, String> reported) {
        this.base = base;
        this.reported = reported;
    }

    /** Whether this machine has what the fixture needs. */
    static boolean available() {
        if (!Files.isExecutable(SCRIPT) || !Files.isExecutable(OPENSSL)) {
            return false;
        }
        for (String binary : BINARIES) {
            if (onPath(binary) == null) {
                return false;
            }
        }
        return true;
    }

    /** Provision a PKI and a server, and wait for it to listen. */
    static StockXrootd start() throws IOException, InterruptedException {
        Path base = Files.createTempDirectory("jroot-interop");
        Process process = new ProcessBuilder(SCRIPT.toAbsolutePath().toString(),
                "start", base.toString(), String.valueOf(freePort()))
                .redirectErrorStream(true)
                .start();
        String output = new String(process.getInputStream().readAllBytes(),
                StandardCharsets.UTF_8);
        if (!process.waitFor(3, TimeUnit.MINUTES)) {
            process.destroyForcibly();
            throw new IOException("the xrootd fixture did not finish starting");
        }
        if (process.exitValue() != 0) {
            throw new IOException("the xrootd fixture failed:\n" + output);
        }
        Map<String, String> reported = new HashMap<>();
        for (String line : output.split("\n")) {
            int split = line.indexOf('=');
            if (split > 0) {
                reported.put(line.substring(0, split), line.substring(split + 1).trim());
            }
        }
        return new StockXrootd(base, reported);
    }

    /** {@code root://host:port//gsidata} — the exported directory itself. */
    String url() {
        return reported.get("url");
    }

    String url(String name) {
        return url() + "/" + name;
    }

    /** Where the server keeps the exported directory on local disk, so a test
     *  can check what arrived without asking the client that sent it. */
    Path storage() {
        return Path.of(reported.get("storage"));
    }

    Path proxy() {
        return Path.of(reported.get("proxy"));
    }

    Path certificates() {
        return Path.of(reported.get("certs"));
    }

    /** The server's own log, worth quoting when a test fails. */
    String log() {
        try {
            return Files.readString(Path.of(reported.get("log")));
        } catch (IOException e) {
            return "(no log: " + e.getMessage() + ")";
        }
    }

    @Override
    public void close() throws IOException, InterruptedException {
        new ProcessBuilder(SCRIPT.toAbsolutePath().toString(), "stop", base.toString())
                .redirectErrorStream(true).start().waitFor(30, TimeUnit.SECONDS);
        try (var paths = Files.walk(base)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> path.toFile().delete());
        }
    }

    private static Path onPath(String binary) {
        for (String entry : System.getenv().getOrDefault("PATH", "").split(":")) {
            Path candidate = Path.of(entry, binary);
            if (Files.isExecutable(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}

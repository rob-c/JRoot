package io.github.robc.jroot.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdConnectionException;
import io.github.robc.jroot.util.Trace;
import io.github.robc.jroot.wire.WBuf;
import io.github.robc.jroot.wire.XrdConst;

/**
 * What happens to an open file when the session under it goes away.
 *
 * <p>The server here is real and so is the socket: {@code dropConnections}
 * closes the session the way a restarted daemon does, and everything after
 * that is the client deciding for itself whether the file can be picked up
 * again.
 */
@Timeout(30)
class RecoveryTest {

    private static final byte[] HANDLE = {1, 2, 3, 4};
    private static final byte[] CONTENT = "the bytes that survive a broken link".getBytes();

    private static Config config() {
        return Config.defaults().withTls(Config.Tls.DISABLED)
                .withRecoveryWindow(Duration.ofSeconds(10));
    }

    /** A server that serves one file and counts the opens it grants. */
    private static MockXrootd fileServer(AtomicInteger opens) throws IOException {
        return fileServer(opens, Integer.MAX_VALUE);
    }

    /** The same, willing to open the file only {@code grants} times: what a
     *  server whose file went away between two opens looks like. */
    private static MockXrootd fileServer(AtomicInteger opens, int grants) throws IOException {
        MockXrootd server = new MockXrootd();
        server.on(XrdConst.kXR_open, MockXrootd.answering(request -> {
            if (opens.incrementAndGet() > grants) {
                return MockXrootd.Reply.error(XrdConst.kXR_NotFound, "no such file");
            }
            return MockXrootd.Reply.ok(new WBuf().raw(HANDLE)
                    .i32(XrdConst.kXR_pgPageSZ).text("adlr", false)
                    .raw(MockXrootd.statLine("id", CONTENT.length, 0, 7)).bytes());
        })).on(XrdConst.kXR_read, MockXrootd.answering(request -> {
            int from = (int) Math.min(request.offset(), CONTENT.length);
            int to = (int) Math.min(from + (long) request.length(), CONTENT.length);
            byte[] slice = new byte[to - from];
            System.arraycopy(CONTENT, from, slice, 0, slice.length);
            return MockXrootd.Reply.ok(slice);
        }));
        return server;
    }

    /** The options a request asked to open with. */
    private static int optionsOf(MockXrootd.Request request) {
        return ((request.params()[2] & 0xFF) << 8) | (request.params()[3] & 0xFF);
    }

    private static List<MockXrootd.Request> opens(MockXrootd server) {
        List<MockXrootd.Request> out = new ArrayList<>();
        for (MockXrootd.Request request : server.requests()) {
            if (request.opcode() == XrdConst.kXR_open) {
                out.add(request);
            }
        }
        return out;
    }

    @Test
    void readsOnAfterTheServerDropsTheSession() throws IOException {
        AtomicInteger opens = new AtomicInteger();
        try (MockXrootd server = fileServer(opens);
                XrdClient client = new XrdClient(config())) {
            XrdFile file = client.open(server.url("data"));
            assertArrayEquals(CONTENT, file.read(0, CONTENT.length));

            server.dropConnections();

            assertArrayEquals(CONTENT, file.read(0, CONTENT.length));
            assertEquals(2, opens.get(), "the file should have been opened again");
            file.close();
        }
    }

    @Test
    void reopensWithoutTheFlagsThatWouldEmptyTheFile() throws IOException {
        AtomicInteger opens = new AtomicInteger();
        Map<Long, byte[]> written = new ConcurrentHashMap<>();
        try (MockXrootd server = fileServer(opens);
                XrdClient client = new XrdClient(config())) {
            server.on(XrdConst.kXR_write, MockXrootd.answering(request -> {
                written.put(request.offset(), request.payload());
                return MockXrootd.Reply.ok(new byte[0]);
            }));
            XrdFile file = client.create(server.url("data"), 0644);
            file.write(0, "first".getBytes());

            server.dropConnections();
            file.write(5, "second".getBytes());

            List<MockXrootd.Request> opened = opens(server);
            assertEquals(2, opened.size());
            int first = optionsOf(opened.get(0));
            int again = optionsOf(opened.get(1));
            assertTrue((first & XrdConst.kXR_delete) != 0, "the first open creates the file");
            assertEquals(0, again & (XrdConst.kXR_delete | XrdConst.kXR_new),
                    "reopening must not throw away what was already written");
            assertTrue((again & XrdConst.kXR_open_updt) != 0, "and must still be writable");
            assertArrayEquals("second".getBytes(), written.get(5L));
            file.close();
        }
    }

    @Test
    void recoversOnceHoweverManyThreadsNoticedTheBreak() throws Exception {
        AtomicInteger opens = new AtomicInteger();
        try (MockXrootd server = fileServer(opens);
                XrdClient client = new XrdClient(config())) {
            XrdFile file = client.open(server.url("data"));
            file.read(0, 4);
            server.dropConnections();

            int readers = 8;
            CountDownLatch ready = new CountDownLatch(readers);
            CountDownLatch go = new CountDownLatch(1);
            CountDownLatch done = new CountDownLatch(readers);
            List<Throwable> failures = new ArrayList<>();
            for (int i = 0; i < readers; i++) {
                Thread thread = new Thread(() -> {
                    ready.countDown();
                    try {
                        go.await();
                        assertArrayEquals(CONTENT, file.read(0, CONTENT.length));
                    } catch (Throwable e) {
                        synchronized (failures) {
                            failures.add(e);
                        }
                    } finally {
                        done.countDown();
                    }
                });
                thread.setDaemon(true);
                thread.start();
            }
            assertTrue(ready.await(10, TimeUnit.SECONDS));
            go.countDown();
            assertTrue(done.await(20, TimeUnit.SECONDS));

            assertEquals(List.of(), failures);
            assertEquals(2, opens.get(), "one break is one reopen, not one per thread");
            file.close();
        }
    }

    @Test
    void leavesTheBreakToTheCallerWhenRecoveryIsTurnedOff() throws IOException {
        AtomicInteger opens = new AtomicInteger();
        try (MockXrootd server = fileServer(opens);
                XrdClient client = new XrdClient(config().withRecoveryWindow(Duration.ZERO))) {
            XrdFile file = client.open(server.url("data"));
            file.read(0, 4);
            server.dropConnections();

            assertThrows(XrdConnectionException.class, () -> file.read(0, 4));
            assertEquals(1, opens.get());
        }
    }

    @Test
    void doesNotKeepTryingWhenTheServerHasAnAnswer() throws IOException {
        AtomicInteger opens = new AtomicInteger();
        try (MockXrootd server = fileServer(opens, 1);
                XrdClient client = new XrdClient(config())) {
            XrdFile file = client.open(server.url("data"));
            file.read(0, 4);
            server.dropConnections();

            long started = System.nanoTime();
            XrdConnectionException failure =
                    assertThrows(XrdConnectionException.class, () -> file.read(0, 4));
            assertTrue(Duration.ofNanos(System.nanoTime() - started).toSeconds() < 5,
                    "a server that answered has settled the question");
            assertTrue(failure.getMessage().contains("will not open it again"),
                    failure.getMessage());
            assertEquals(2, opens.get(), "asked once, told no, and stopped asking");
        }
    }

    @Test
    void givesUpWhenTheServerDoesNotComeBack() throws IOException {
        AtomicInteger opens = new AtomicInteger();
        try (MockXrootd server = fileServer(opens);
                XrdClient client = new XrdClient(
                        config().withRecoveryWindow(Duration.ofSeconds(1)))) {
            XrdFile file = client.open(server.url("data"));
            file.read(0, 4);
            server.close();

            XrdConnectionException failure =
                    assertThrows(XrdConnectionException.class, () -> file.read(0, 4));
            assertTrue(failure.getMessage().contains("could not be reopened within 1s"),
                    failure.getMessage());
        }
    }

    @Test
    void willNotRebuildACheckpointItCannotHave() throws IOException {
        AtomicInteger opens = new AtomicInteger();
        try (MockXrootd server = fileServer(opens);
                XrdClient client = new XrdClient(config())) {
            XrdFile file = client.open(server.url("data"),
                    XrdConst.kXR_open_updt | XrdConst.kXR_retstat, 0644);
            file.checkpoint();
            server.dropConnections();

            assertThrows(XrdConnectionException.class, file::commit);
            assertEquals(1, opens.get(),
                    "a checkpoint lives on the server; reopening would silently drop it");
        }
    }

    /**
     * The trace is the only account of a recovery anybody gets, and a client
     * nobody has ever turned the trace up on is a client whose trace is
     * wrong: a format string with the wrong number of arguments says
     * "unformattable" instead of what happened, and only a run with the
     * levels open finds that.
     */
    @Test
    void saysWhatItDidWhenAnyoneIsListening() throws IOException {
        ByteArrayOutputStream written = new ByteArrayOutputStream();
        Trace.configure(Trace.Level.DUMP,
                new PrintStream(written, true, StandardCharsets.UTF_8), Set.of());
        AtomicInteger opens = new AtomicInteger();
        try (MockXrootd server = fileServer(opens);
                XrdClient client = new XrdClient(config())) {
            XrdFile file = client.open(server.url("data"));
            file.read(0, 4);
            server.dropConnections();
            file.read(0, 4);
            file.close();
        } finally {
            Trace.fromEnvironment();
        }
        String trace = written.toString(StandardCharsets.UTF_8);
        assertFalse(trace.contains("unformattable"), trace);
        assertTrue(trace.contains("connected to"), trace);
        assertTrue(trace.contains("logging in as"), trace);
        assertTrue(trace.contains("-> kXR_read"), trace);
        assertTrue(trace.contains("session lost"), trace);
        assertTrue(trace.contains("session rebuilt"), trace);
    }

    @Test
    void closesAFileWhoseServerHasAlreadyGone() throws IOException {
        AtomicInteger opens = new AtomicInteger();
        try (MockXrootd server = fileServer(opens);
                XrdClient client = new XrdClient(config())) {
            XrdFile file = client.open(server.url("data"));
            file.read(0, 4);
            server.dropConnections();

            file.close();                           // the handle went with the session
            assertEquals(1, opens.get(), "closing is not worth a reconnection");
        }
    }
}

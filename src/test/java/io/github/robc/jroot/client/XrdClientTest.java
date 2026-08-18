package io.github.robc.jroot.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdServerException;
import io.github.robc.jroot.wire.Types.DirEntry;
import io.github.robc.jroot.wire.Types.StatInfo;
import io.github.robc.jroot.wire.WBuf;
import io.github.robc.jroot.wire.XrdConst;

/** End-to-end tests: a real client against a real socket speaking real frames. */
@Timeout(30)
class XrdClientTest {

    private static final byte[] CONTENT =
            "the quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);

    private static Config config() {
        return Config.defaults().withTls(Config.Tls.DISABLED).withAllowUnix(true);
    }

    @Test
    void bringsUpASessionAndStats() throws IOException {
        try (MockXrootd server = new MockXrootd()) {
            server.on(XrdConst.kXR_stat, MockXrootd.answering(request ->
                    MockXrootd.Reply.ok(MockXrootd.statLine("id0", 1234, XrdConst.kXR_readable, 99))));
            try (XrdClient client = new XrdClient(config())) {
                StatInfo stat = client.stat(server.url("/data/file"));
                assertEquals(1234, stat.size());
                assertEquals(99, stat.mtime());
                assertTrue(stat.isReadable());
            }
            // handshake, protocol, login, stat, endsess — in that order
            assertEquals(List.of(XrdConst.kXR_protocol, XrdConst.kXR_login,
                    XrdConst.kXR_stat, XrdConst.kXR_endsess), server.opcodes());
        }
    }

    @Test
    void sendsThePathItWasGiven() throws IOException {
        try (MockXrootd server = new MockXrootd()) {
            server.on(XrdConst.kXR_stat, MockXrootd.answering(request ->
                    MockXrootd.Reply.ok(MockXrootd.statLine("id", 0, 0, 0))));
            try (XrdClient client = new XrdClient(config())) {
                client.stat(server.url("/store/data/file.root?authz=abc"));
            }
            MockXrootd.Request stat = server.requests().stream()
                    .filter(request -> request.opcode() == XrdConst.kXR_stat)
                    .findFirst().orElseThrow();
            assertEquals("/store/data/file.root?authz=abc", stat.text());
        }
    }

    @Test
    void readsAFileThroughAnOpenHandle() throws IOException {
        try (MockXrootd server = new MockXrootd()) {
            server.on(XrdConst.kXR_open, MockXrootd.answering(request ->
                            MockXrootd.Reply.ok(new WBuf()
                                    .raw(new byte[] {1, 2, 3, 4})
                                    .i32(XrdConst.kXR_pgPageSZ).text("adlr", false)
                                    .raw(MockXrootd.statLine("id", CONTENT.length, 0, 7))
                                    .bytes())))
                    .on(XrdConst.kXR_read, MockXrootd.answering(request -> {
                        int from = (int) request.offset();
                        int length = Math.min(request.length(), CONTENT.length - from);
                        byte[] slice = new byte[Math.max(length, 0)];
                        System.arraycopy(CONTENT, from, slice, 0, slice.length);
                        return MockXrootd.Reply.ok(slice);
                    }));
            try (XrdClient client = new XrdClient(config());
                 XrdFile file = client.open(server.url("/data/file"))) {
                assertEquals(CONTENT.length, file.size());
                assertArrayEquals("quick".getBytes(StandardCharsets.UTF_8), file.read(4, 5));
                assertArrayEquals(CONTENT, file.readAll(8));
            }
        }
    }

    @Test
    void accumulatesAnOksofarReply() throws IOException {
        try (MockXrootd server = new MockXrootd()) {
            server.on(XrdConst.kXR_open, MockXrootd.answering(request ->
                            MockXrootd.Reply.ok(new byte[] {9, 9, 9, 9})))
                    .on(XrdConst.kXR_read, request -> {
                        int half = CONTENT.length / 2;
                        byte[] first = new byte[half];
                        byte[] rest = new byte[CONTENT.length - half];
                        System.arraycopy(CONTENT, 0, first, 0, half);
                        System.arraycopy(CONTENT, half, rest, 0, rest.length);
                        return List.of(MockXrootd.Reply.oksofar(first),
                                MockXrootd.Reply.ok(rest));
                    });
            try (XrdClient client = new XrdClient(config());
                 XrdFile file = client.open(server.url("/data/file"))) {
                assertArrayEquals(CONTENT, file.read(0, CONTENT.length));
            }
        }
    }

    @Test
    void waitsAndResendsWhenAskedTo() throws IOException {
        try (MockXrootd server = new MockXrootd()) {
            server.on(XrdConst.kXR_stat, new WaitOnce());
            try (XrdClient client = new XrdClient(config())) {
                assertEquals(42, client.stat(server.url("/data/file")).size());
            }
            long stats = server.opcodes().stream()
                    .filter(opcode -> opcode == XrdConst.kXR_stat).count();
            assertEquals(2, stats, "the client should have sent the request again");
        }
    }

    /** Asks the client to wait once, then answers properly. */
    private static final class WaitOnce implements MockXrootd.Handler {
        private boolean asked;

        @Override
        public List<MockXrootd.Reply> handle(MockXrootd.Request request) {
            if (!asked) {
                asked = true;
                return List.of(MockXrootd.Reply.wait(0, "come back"));
            }
            return List.of(MockXrootd.Reply.ok(MockXrootd.statLine("id", 42, 0, 0)));
        }
    }

    @Test
    void followsARedirectToAnotherServer() throws IOException {
        try (MockXrootd manager = new MockXrootd();
             MockXrootd data = new MockXrootd()) {
            data.on(XrdConst.kXR_stat, MockXrootd.answering(request ->
                    MockXrootd.Reply.ok(MockXrootd.statLine("id", 7, 0, 0))));
            manager.on(XrdConst.kXR_stat, MockXrootd.answering(request ->
                    MockXrootd.Reply.redirect(data.port(), "127.0.0.1?token=xyz")));
            try (XrdClient client = new XrdClient(config())) {
                assertEquals(7, client.stat(manager.url("/data/file")).size());
            }
            MockXrootd.Request stat = data.requests().stream()
                    .filter(request -> request.opcode() == XrdConst.kXR_stat)
                    .findFirst().orElseThrow();
            assertTrue(stat.text().contains("token=xyz"),
                    "the redirect's opaque data must travel with the retried request: "
                            + stat.text());
        }
    }

    @Test
    void surfacesAServerErrorWithItsCode() throws IOException {
        try (MockXrootd server = new MockXrootd()) {
            server.on(XrdConst.kXR_stat, MockXrootd.answering(request ->
                    MockXrootd.Reply.error(XrdConst.kXR_NotFound, "no such file")));
            try (XrdClient client = new XrdClient(config())) {
                XrdServerException failure = assertThrows(XrdServerException.class,
                        () -> client.stat(server.url("/data/missing")));
                assertEquals(XrdConst.kXR_NotFound, failure.code());
                assertTrue(failure.isNotFound());
                assertTrue(failure.getMessage().contains("no such file"));
                assertFalse(client.exists(server.url("/data/missing")));
            }
        }
    }

    @Test
    void listsADirectoryWithStat() throws IOException {
        try (MockXrootd server = new MockXrootd()) {
            server.on(XrdConst.kXR_dirlist, MockXrootd.answering(request -> MockXrootd.Reply.ok(
                    ".\n0 0 " + XrdConst.kXR_isDir + " 0\n"
                            + "one.root\nid1 100 0 11\n"
                            + "sub\nid2 0 " + XrdConst.kXR_isDir + " 12\n")));
            try (XrdClient client = new XrdClient(config())) {
                List<DirEntry> entries = client.list(server.url("/data"));
                assertEquals(2, entries.size());
                assertEquals("one.root", entries.get(0).name());
                assertEquals(100, entries.get(0).stat().orElseThrow().size());
                assertTrue(entries.get(1).isDirectory());
                assertEquals("/data/sub", entries.get(1).stat().orElseThrow().path());
            }
        }
    }

    @Test
    void refusesADirectoryEntryThatWouldEscapeItsParent() throws IOException {
        try (MockXrootd server = new MockXrootd()) {
            server.on(XrdConst.kXR_dirlist, MockXrootd.answering(request ->
                    MockXrootd.Reply.ok(".\n0 0 2 0\n../../.ssh/authorized_keys\nid 1 0 0\n")));
            try (XrdClient client = new XrdClient(config())) {
                assertThrows(RuntimeException.class, () -> client.list(server.url("/data")));
            }
        }
    }

    @Test
    void writesAndCloses() throws IOException {
        try (MockXrootd server = new MockXrootd()) {
            server.on(XrdConst.kXR_open, MockXrootd.answering(request ->
                    MockXrootd.Reply.ok(new byte[] {5, 6, 7, 8})));
            try (XrdClient client = new XrdClient(config())) {
                client.write(server.url("/data/new"), CONTENT);
            }
            MockXrootd.Request write = server.requests().stream()
                    .filter(request -> request.opcode() == XrdConst.kXR_write)
                    .findFirst().orElseThrow();
            assertArrayEquals(CONTENT, write.payload());
            assertArrayEquals(new byte[] {5, 6, 7, 8},
                    new byte[] {write.params()[0], write.params()[1],
                            write.params()[2], write.params()[3]});
            assertTrue(server.opcodes().contains(XrdConst.kXR_close));
        }
    }

    @Test
    void reusesOneConnectionPerServer() throws IOException {
        try (MockXrootd server = new MockXrootd()) {
            server.on(XrdConst.kXR_stat, MockXrootd.answering(request ->
                    MockXrootd.Reply.ok(MockXrootd.statLine("id", 1, 0, 0))));
            try (XrdClient client = new XrdClient(config())) {
                client.stat(server.url("/a"));
                client.stat(server.url("/b"));
                client.ping(server.url("/a"));
            }
            long logins = server.opcodes().stream()
                    .filter(opcode -> opcode == XrdConst.kXR_login).count();
            assertEquals(1, logins, "three operations should share one session");
        }
    }
}

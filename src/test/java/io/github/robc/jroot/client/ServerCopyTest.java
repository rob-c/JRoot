package io.github.robc.jroot.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdException;
import io.github.robc.jroot.wire.Requests;
import io.github.robc.jroot.wire.WBuf;
import io.github.robc.jroot.wire.XrdConst;

/**
 * The copies a server does for itself: XRootD-native third-party copy, the
 * {@code kXR_gpfile} request, and {@code kXR_clone}.
 */
@Timeout(30)
class ServerCopyTest {

    private static final long SIZE = 4096;

    private static Config config() {
        return Config.defaults().withTls(Config.Tls.DISABLED).withAllowUnix(true);
    }

    /** Answers every open with a handle, so the server can be pointed at
     *  whichever end of a copy the test needs. */
    private static MockXrootd opening(byte[] handle) throws IOException {
        MockXrootd server = new MockXrootd();
        server.on(XrdConst.kXR_open, MockXrootd.answering(request ->
                MockXrootd.Reply.ok(new WBuf().raw(handle)
                        .i32(XrdConst.kXR_pgPageSZ).text("adlr", false)
                        .raw(MockXrootd.statLine("id", SIZE, 0, 7)).bytes())));
        return server;
    }

    private static List<String> opens(MockXrootd server) {
        List<String> out = new ArrayList<>();
        for (MockXrootd.Request request : server.requests()) {
            if (request.opcode() == XrdConst.kXR_open) {
                out.add(request.text());
            }
        }
        return out;
    }

    private static String value(String opaque, String key) {
        for (String field : opaque.substring(opaque.indexOf('?') + 1).split("&")) {
            if (field.startsWith(key + "=")) {
                return field.substring(key.length() + 1);
            }
        }
        throw new AssertionError(key + " is not in " + opaque);
    }

    @Test
    void rendezvousesTheTwoServersOnOneKey() throws IOException {
        try (MockXrootd source = opening(new byte[] {1, 1, 1, 1});
             MockXrootd target = opening(new byte[] {2, 2, 2, 2})) {
            source.on(XrdConst.kXR_stat, MockXrootd.answering(request ->
                    MockXrootd.Reply.ok(MockXrootd.statLine("id", SIZE, 0, 7))));
            try (XrdClient client = new XrdClient(config())) {
                client.thirdPartyCopy(source.url("/store/in.root"), target.url("/store/out.root"));
            }

            // The source is asked to place the file, then to coordinate the copy.
            List<String> sourceOpens = opens(source);
            assertEquals(2, sourceOpens.size());
            assertEquals("placement", value(sourceOpens.get(0), "tpc.stage"));
            String coordinator = sourceOpens.get(1);
            assertEquals("copy", value(coordinator, "tpc.stage"));

            String destination = opens(target).get(0);
            assertEquals(value(coordinator, "tpc.key"), value(destination, "tpc.key"),
                    "both ends must name the same rendezvous key");
            assertEquals(24, value(coordinator, "tpc.key").length());
            assertEquals(String.valueOf(SIZE), value(destination, "oss.asize"));
            assertEquals("/store/in.root", value(destination, "tpc.lfn"));
            assertEquals("root", value(destination, "tpc.spr"));
            assertEquals("root", value(destination, "tpc.tpr"));
            assertTrue(destination.startsWith("/store/out.root?"), destination);
            assertTrue(value(coordinator, "tpc.dst").startsWith("127.0.0.1"),
                    "the source is told where the file is going: " + coordinator);
        }
    }

    @Test
    void namesTheServerThePlacementProbeLandedOn() throws IOException {
        try (MockXrootd manager = new MockXrootd();
             MockXrootd dataServer = opening(new byte[] {3, 3, 3, 3});
             MockXrootd target = opening(new byte[] {4, 4, 4, 4})) {
            manager.on(XrdConst.kXR_stat, MockXrootd.answering(request ->
                            MockXrootd.Reply.ok(MockXrootd.statLine("id", SIZE, 0, 7))))
                    .on(XrdConst.kXR_open, MockXrootd.answering(request ->
                            MockXrootd.Reply.redirect(dataServer.port(), "127.0.0.1")));
            try (XrdClient client = new XrdClient(config())) {
                client.thirdPartyCopy(manager.url("/store/in.root"), target.url("/store/out.root"));
            }
            // The key is registered where the probe landed, so that is the
            // address the destination must pull from - not the manager's.
            String destination = opens(target).get(0);
            String endpoint = "127.0.0.1:" + dataServer.port();
            assertEquals(endpoint, value(destination, "tpc.src"));
            assertEquals(endpoint, value(destination, "tpc.dlg"));
        }
    }

    @Test
    void startsTheCopyAndWaitsForIt() throws IOException {
        try (MockXrootd source = opening(new byte[] {1, 1, 1, 1});
             MockXrootd target = opening(new byte[] {2, 2, 2, 2})) {
            source.on(XrdConst.kXR_stat, MockXrootd.answering(request ->
                    MockXrootd.Reply.ok(MockXrootd.statLine("id", SIZE, 0, 7))));
            try (XrdClient client = new XrdClient(config())) {
                client.thirdPartyCopy(source.url("/store/in.root"), target.url("/store/out.root"));
            }
            // Two syncs: one to start the transfer, one that does not answer
            // until it has finished.
            assertEquals(2, target.opcodes().stream()
                    .filter(opcode -> opcode == XrdConst.kXR_sync).count());
            assertTrue(target.opcodes().contains(XrdConst.kXR_close));
        }
    }

    @Test
    void allowsFarLongerForTheSyncThatWaitsOutTheTransfer() {
        Config brisk = config().withRequestTimeout(java.time.Duration.ofSeconds(30));
        try (XrdClient client = new XrdClient(brisk)) {
            assertEquals(java.time.Duration.ofHours(1), client.tpcTimeout());
        }
        Config patient = config().withRequestTimeout(java.time.Duration.ofHours(6));
        try (XrdClient client = new XrdClient(patient)) {
            assertEquals(java.time.Duration.ofHours(6), client.tpcTimeout());
        }
    }

    @Test
    void asksTheServerToGetAFileForItself() throws IOException {
        try (MockXrootd server = new MockXrootd()) {
            server.on(XrdConst.kXR_gpfile, MockXrootd.answering(request ->
                    MockXrootd.Reply.ok("request-42\n")));
            try (XrdClient client = new XrdClient(config())) {
                assertEquals("request-42", client.getPutFile(
                        server.url("/store/file.root"), XrdConst.kXR_gpfGet, 1 << 20));
            }
            MockXrootd.Request request = server.requests().stream()
                    .filter(seen -> seen.opcode() == XrdConst.kXR_gpfile)
                    .findFirst().orElseThrow();
            assertEquals(XrdConst.kXR_gpfGet, be32(request.params(), 0));
            assertEquals(1 << 20, be32(request.params(), 12));
            assertEquals("/store/file.root", request.text());
        }
    }

    @Test
    void clonesRangesBetweenTwoOpenFiles() throws IOException {
        try (MockXrootd server = new MockXrootd()) {
            List<byte[]> handles = List.of(new byte[] {1, 0, 0, 0}, new byte[] {2, 0, 0, 0});
            java.util.concurrent.atomic.AtomicInteger next =
                    new java.util.concurrent.atomic.AtomicInteger();
            server.on(XrdConst.kXR_open, MockXrootd.answering(request ->
                    MockXrootd.Reply.ok(handles.get(next.getAndIncrement() % handles.size()))));
            try (XrdClient client = new XrdClient(config());
                 XrdFile source = client.open(server.url("/store/in.root"));
                 XrdFile target = client.open(server.url("/store/out.root"),
                         XrdConst.kXR_open_updt, XrdConst.DEFAULT_FILE_MODE)) {
                target.cloneFrom(source, 128, 4096, 0);
            }
            MockXrootd.Request clone = server.requests().stream()
                    .filter(request -> request.opcode() == XrdConst.kXR_clone)
                    .findFirst().orElseThrow();
            assertEquals(XrdConst.CLONE_ITEM_LEN, clone.payload().length);
            assertEquals(2, clone.params()[0], "the destination handle goes in the parameters");
            assertEquals(1, clone.payload()[0], "the source handle goes in the item");
            assertEquals(128, be64(clone.payload(), 8));
            assertEquals(4096, be64(clone.payload(), 16));
            assertEquals(0, be64(clone.payload(), 24));
        }
    }

    @Test
    void splitsALongCloneAtTheServersItemLimit() throws IOException {
        try (MockXrootd server = new MockXrootd()) {
            server.on(XrdConst.kXR_open, MockXrootd.answering(request ->
                    MockXrootd.Reply.ok(new byte[] {1, 0, 0, 0})));
            try (XrdClient client = new XrdClient(config());
                 XrdFile target = client.open(server.url("/store/out.root"),
                         XrdConst.kXR_open_updt, XrdConst.DEFAULT_FILE_MODE)) {
                List<Requests.CloneItem> items = new ArrayList<>();
                for (int i = 0; i < XrdConst.CLONE_MAXITEMS + 1; i++) {
                    items.add(new Requests.CloneItem(target.handle(), i * 512L, 512, i * 512L));
                }
                target.cloneFrom(items);
            }
            List<MockXrootd.Request> clones = server.requests().stream()
                    .filter(request -> request.opcode() == XrdConst.kXR_clone).toList();
            assertEquals(2, clones.size());
            assertEquals(XrdConst.CLONE_MAXITEMS * XrdConst.CLONE_ITEM_LEN,
                    clones.get(0).payload().length);
            assertEquals(XrdConst.CLONE_ITEM_LEN, clones.get(1).payload().length);
        }
    }

    @Test
    void refusesToCloneAcrossTwoConnections() throws IOException {
        try (MockXrootd one = opening(new byte[] {1, 0, 0, 0});
             MockXrootd two = opening(new byte[] {2, 0, 0, 0});
             XrdClient client = new XrdClient(config());
             XrdFile source = client.open(one.url("/store/in.root"));
             XrdFile target = client.open(two.url("/store/out.root"),
                     XrdConst.kXR_open_updt, XrdConst.DEFAULT_FILE_MODE)) {
            XrdException e = assertThrows(XrdException.class,
                    () -> target.cloneFrom(source, 0, 16, 0));
            assertTrue(e.getMessage().contains("another connection"), e.getMessage());
        }
    }

    private static long be64(byte[] data, int at) {
        long value = 0;
        for (int i = at; i < at + 8; i++) {
            value = (value << 8) | (data[i] & 0xFF);
        }
        return value;
    }

    private static int be32(byte[] data, int at) {
        int value = 0;
        for (int i = at; i < at + 4; i++) {
            value = (value << 8) | (data[i] & 0xFF);
        }
        return value;
    }
}

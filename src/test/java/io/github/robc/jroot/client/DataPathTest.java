package io.github.robc.jroot.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.wire.WBuf;
import io.github.robc.jroot.wire.XrdConst;

/**
 * Multi-stream I/O: {@code kXR_bind}, and the split frames that make binding
 * worth doing — the header on the control link, the bulk bytes on the path.
 */
@Timeout(30)
class DataPathTest {

    private static final byte[] HANDLE = {1, 2, 3, 4};
    private static final int SIZE = 64 * 1024;

    private static Config config(int streams) {
        return Config.defaults().withTls(Config.Tls.DISABLED).withAllowUnix(true)
                .withDataStreams(streams);
    }

    /** A file whose byte at offset {@code i} is {@code i}, so a chunk that
     *  lands at the wrong offset is visible in the assertion. */
    private static byte[] content() {
        byte[] out = new byte[SIZE];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) i;
        }
        return out;
    }

    private static MockXrootd serving(byte[] content) throws IOException {
        MockXrootd server = new MockXrootd();
        server.on(XrdConst.kXR_open, MockXrootd.answering(request ->
                        MockXrootd.Reply.ok(new WBuf().raw(HANDLE)
                                .i32(XrdConst.kXR_pgPageSZ).text("adlr", false)
                                .raw(MockXrootd.statLine("id", content.length, 0, 7))
                                .bytes())))
                .on(XrdConst.kXR_read, MockXrootd.answering(request -> {
                    // A read that starts past the end is answered with nothing,
                    // which is what a real server does at EOF.
                    int from = (int) Math.min(request.offset(), content.length);
                    int length = Math.max(Math.min(request.length(), content.length - from), 0);
                    return MockXrootd.Reply.ok(Arrays.copyOfRange(content, from, from + length));
                }));
        return server;
    }

    @Test
    void bindsTheStreamsItWasConfiguredFor() throws IOException {
        byte[] content = content();
        try (MockXrootd server = serving(content)) {
            try (XrdClient client = new XrdClient(config(4));
                 XrdFile file = client.open(server.url("/data/file"))) {
                assertEquals(List.of(1, 2, 3), server.boundPaths());
                // Three bound paths plus the control link, which is path 0.
                assertArrayEquals(new int[] {0, 1, 2, 3}, file.streams());
                assertArrayEquals(content, file.readAll(4096));
            }
            assertEquals(3, server.opcodes().stream()
                    .filter(opcode -> opcode == XrdConst.kXR_bind).count());
        }
    }

    @Test
    void spreadsOneReadOverEveryStream() throws IOException {
        byte[] content = content();
        try (MockXrootd server = serving(content)) {
            try (XrdClient client = new XrdClient(config(3));
                 XrdFile file = client.open(server.url("/data/file"))) {
                assertArrayEquals(content, file.readAcross(0, SIZE, 4096));
            }
            List<Integer> used = new ArrayList<>();
            for (MockXrootd.Request request : server.requests()) {
                if (request.opcode() == XrdConst.kXR_read && !used.contains(request.pathId())) {
                    used.add(request.pathId());
                }
            }
            assertEquals(List.of(0, 1, 2), used.stream().sorted().toList());
        }
    }

    @Test
    void readsTheRightBytesAtTheRightOffsets() throws IOException {
        byte[] content = content();
        try (MockXrootd server = serving(content)) {
            try (XrdClient client = new XrdClient(config(3));
                 XrdFile file = client.open(server.url("/data/file"))) {
                // A length that is not a whole number of chunks, at an offset
                // that is not a chunk boundary: the arithmetic has nowhere to hide.
                assertArrayEquals(Arrays.copyOfRange(content, 1000, 1000 + 5000),
                        file.readAcross(1000, 5000, 1024));
            }
        }
    }

    @Test
    void stopsAtTheEndOfAShortFile() throws IOException {
        byte[] content = content();
        try (MockXrootd server = serving(content)) {
            try (XrdClient client = new XrdClient(config(3));
                 XrdFile file = client.open(server.url("/data/file"))) {
                byte[] read = file.readAcross(SIZE - 100, 4096, 512);
                assertEquals(100, read.length);
                assertArrayEquals(Arrays.copyOfRange(content, SIZE - 100, SIZE), read);
            }
        }
    }

    @Test
    void sendsAWritesDataDownThePathAndItsHeaderUpTheControlLink() throws IOException {
        byte[] content = content();
        Map<Long, byte[]> written = new ConcurrentHashMap<>();
        try (MockXrootd server = serving(content)) {
            server.on(XrdConst.kXR_write, MockXrootd.answering(request -> {
                written.put(request.offset(), request.payload());
                return MockXrootd.Reply.ok(new byte[0]);
            }));
            try (XrdClient client = new XrdClient(config(3));
                 XrdFile file = client.open(server.url("/data/file"),
                         XrdConst.kXR_open_updt, XrdConst.DEFAULT_FILE_MODE)) {
                file.writeAcross(0, content, 8192);
            }
            byte[] reassembled = new byte[SIZE];
            written.forEach((offset, data) ->
                    System.arraycopy(data, 0, reassembled, offset.intValue(), data.length));
            assertArrayEquals(content, reassembled);
            assertEquals(SIZE / 8192, written.size());
            assertTrue(server.requests().stream()
                    .filter(request -> request.opcode() == XrdConst.kXR_write)
                    .anyMatch(request -> request.pathId() != 0),
                    "at least one write should have gone down a bound path");
        }
    }

    @Test
    void keepsWorkingWhenTheServerWillNotBind() throws IOException {
        byte[] content = content();
        try (MockXrootd server = serving(content)) {
            server.on(XrdConst.kXR_bind, MockXrootd.answering(request ->
                    MockXrootd.Reply.error(XrdConst.kXR_NotAuthorized, "no extra streams here")));
            try (XrdClient client = new XrdClient(config(4));
                 XrdFile file = client.open(server.url("/data/file"))) {
                assertArrayEquals(new int[] {0}, file.streams());
                assertArrayEquals(content, file.readAll(4096));
            }
        }
    }

    @Test
    void bindsNothingForASingleStreamSession() throws IOException {
        byte[] content = content();
        try (MockXrootd server = serving(content)) {
            try (XrdClient client = new XrdClient(config(1));
                 XrdFile file = client.open(server.url("/data/file"))) {
                assertArrayEquals(new int[] {0}, file.streams());
                assertArrayEquals(content, file.readAll(4096));
            }
            assertFalse(server.opcodes().contains(XrdConst.kXR_bind));
        }
    }

    @Test
    void bindsOncePerSessionHoweverManyFilesAreOpened() throws IOException {
        byte[] content = content();
        try (MockXrootd server = serving(content)) {
            try (XrdClient client = new XrdClient(config(2))) {
                client.open(server.url("/data/one")).close();
                client.open(server.url("/data/two")).close();
            }
            assertEquals(1, server.opcodes().stream()
                    .filter(opcode -> opcode == XrdConst.kXR_bind).count());
        }
    }
}

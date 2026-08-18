package io.github.robc.jroot.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdProtocolException;
import io.github.robc.jroot.wire.PagedIo;
import io.github.robc.jroot.wire.WBuf;
import io.github.robc.jroot.wire.XrdConst;

/**
 * {@code kXR_pgwrite} and the pages a server says it could not trust. The
 * server writes the data either way and reports the offsets whose checksum
 * failed on the way in, so the write is not done until those have been sent
 * again and accepted.
 */
@Timeout(30)
class PagedWriteTest {

    private static final byte[] HANDLE = {1, 2, 3, 4};
    private static final int PAGE = XrdConst.kXR_pgPageSZ;

    private static Config config() {
        return Config.defaults().withTls(Config.Tls.DISABLED).withAllowUnix(true);
    }

    /** Bytes whose value tracks their offset, so a page sent from the wrong
     *  place in the buffer is visible in the assertion. */
    private static byte[] content(int length) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (byte) (i * 31 + 7);
        }
        return out;
    }

    /** The trailer a server sends when it distrusts the pages at {@code offsets}. */
    private static byte[] checksumErrors(long... offsets) {
        WBuf w = new WBuf().u32(0).u16(0).u16(0);       // CRC and the two lengths
        for (long offset : offsets) {
            w.i64(offset);
        }
        return w.bytes();
    }

    private static MockXrootd.Reply cse(long... offsets) {
        return MockXrootd.Reply.status(XrdConst.kXR_pgwrite, XrdConst.kXR_FinalResult,
                new byte[0], checksumErrors(offsets));
    }

    private static MockXrootd.Reply clean() {
        return MockXrootd.Reply.status(XrdConst.kXR_pgwrite, XrdConst.kXR_FinalResult,
                new byte[0], new byte[0]);
    }

    /** What the server answers the n-th {@code kXR_pgwrite} it is sent. */
    private interface Verdicts {
        MockXrootd.Reply of(int attempt);
    }

    private static MockXrootd serving(List<MockXrootd.Request> writes, Verdicts answers)
            throws IOException {
        MockXrootd server = new MockXrootd();
        server.on(XrdConst.kXR_open, MockXrootd.answering(request ->
                        MockXrootd.Reply.ok(new WBuf().raw(HANDLE)
                                .i32(PAGE).text("adlr", false)
                                .raw(MockXrootd.statLine("id", 0, 0, 7))
                                .bytes())))
                .on(XrdConst.kXR_pgwrite, MockXrootd.answering(request -> {
                    writes.add(request);
                    return answers.of(writes.size() - 1);
                }));
        return server;
    }

    /** The reqflags byte, which is where {@code kXR_pgRetry} rides. */
    private static int flags(MockXrootd.Request request) {
        return request.params()[13] & 0xFF;
    }

    /** The bytes of one page, stripped of the framing that carried them. */
    private static byte[] page(MockXrootd.Request request) {
        return PagedIo.unpackPages(request.offset(), request.payload());
    }

    @Test
    void asksNothingMoreWhenEveryPageArrives() throws IOException {
        List<MockXrootd.Request> writes = new ArrayList<>();
        byte[] data = content(3 * PAGE);
        try (MockXrootd server = serving(writes, attempt -> clean());
             XrdClient client = new XrdClient(config());
             XrdFile file = client.open(server.url("/data/f"))) {
            file.pgWrite(0, data);
        }
        assertEquals(1, writes.size());
        assertEquals(0, flags(writes.get(0)));
        assertArrayEquals(data, page(writes.get(0)));
    }

    @Test
    void sendsAgainTheOnePageTheServerDistrusted() throws IOException {
        List<MockXrootd.Request> writes = new ArrayList<>();
        byte[] data = content(3 * PAGE);
        try (MockXrootd server = serving(writes, attempt -> attempt == 0 ? cse(PAGE) : clean());
             XrdClient client = new XrdClient(config());
             XrdFile file = client.open(server.url("/data/f"))) {
            file.pgWrite(0, data);
        }
        assertEquals(2, writes.size());

        // The retry carries that page and no other, at its own file offset,
        // and says what it is - a server that cannot tell a retry from a
        // fresh write has no way to stop asking for it.
        MockXrootd.Request retry = writes.get(1);
        assertEquals(XrdConst.kXR_pgRetry, flags(retry));
        assertEquals(PAGE, retry.offset());
        assertArrayEquals(Arrays.copyOfRange(data, PAGE, 2 * PAGE), page(retry));
    }

    @Test
    void cutsAResentPageOutOfAnUnalignedWrite() throws IOException {
        // A write that starts mid-page: the first page is short, so the
        // second one begins at the boundary rather than at start + 4096.
        List<MockXrootd.Request> writes = new ArrayList<>();
        long start = PAGE / 2;
        byte[] data = content(2 * PAGE);
        try (MockXrootd server = serving(writes,
                        attempt -> attempt == 0 ? cse(PAGE, 2 * PAGE) : clean());
             XrdClient client = new XrdClient(config());
             XrdFile file = client.open(server.url("/data/f"))) {
            file.pgWrite(start, data);
        }
        assertEquals(3, writes.size());

        MockXrootd.Request second = writes.get(1);
        assertEquals(PAGE, second.offset());
        assertArrayEquals(
                Arrays.copyOfRange(data, PAGE / 2, PAGE / 2 + PAGE), page(second));

        // The last page runs to the end of the write, not to a boundary.
        MockXrootd.Request third = writes.get(2);
        assertEquals(2 * PAGE, third.offset());
        assertArrayEquals(
                Arrays.copyOfRange(data, PAGE + PAGE / 2, data.length), page(third));
    }

    @Test
    void givesUpOnAPageThatWillNotStayIntact() throws IOException {
        List<MockXrootd.Request> writes = new ArrayList<>();
        byte[] data = content(PAGE);
        try (MockXrootd server = serving(writes, attempt -> cse(0));
             XrdClient client = new XrdClient(config());
             XrdFile file = client.open(server.url("/data/f"))) {
            XrdProtocolException failure =
                    assertThrows(XrdProtocolException.class, () -> file.pgWrite(0, data));
            assertTrue(failure.getMessage().contains("still corrupt"), failure.getMessage());
        }
        // The first write, then a bounded number of retries: a link that
        // corrupts every attempt is worth failing on, not writing over.
        assertEquals(4, writes.size());
    }

    @Test
    void refusesAnOffsetThatIsNotInTheWrite() throws IOException {
        List<MockXrootd.Request> writes = new ArrayList<>();
        byte[] data = content(PAGE);
        try (MockXrootd server = serving(writes, attempt -> cse(8 * PAGE));
             XrdClient client = new XrdClient(config());
             XrdFile file = client.open(server.url("/data/f"))) {
            XrdProtocolException failure =
                    assertThrows(XrdProtocolException.class, () -> file.pgWrite(0, data));
            assertTrue(failure.getMessage().contains("outside"), failure.getMessage());
        }
        assertEquals(1, writes.size());
    }

    @Test
    void refusesATrailerThatIsNotAListOfOffsets() {
        assertEquals(0, PagedIo.corruptPages(new byte[0]).length);
        assertEquals(0, PagedIo.corruptPages(checksumErrors()).length);
        assertArrayEquals(new long[] {0, PAGE},
                PagedIo.corruptPages(checksumErrors(0, PAGE)));

        XrdProtocolException failure = assertThrows(XrdProtocolException.class,
                () -> PagedIo.corruptPages(new byte[12]));
        assertTrue(failure.getMessage().contains("malformed"), failure.getMessage());
        assertThrows(XrdProtocolException.class, () -> PagedIo.corruptPages(new byte[4]));
    }
}

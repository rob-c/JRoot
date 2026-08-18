package io.github.robc.jroot.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
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
 * {@code kXR_pgread}: pages that arrive under their own checksums, in one
 * frame or several, and what happens when one of them is wrong.
 */
@Timeout(30)
class PagedReadTest {

    private static final byte[] HANDLE = {1, 2, 3, 4};
    private static final int PAGE = XrdConst.kXR_pgPageSZ;

    private static Config config() {
        return Config.defaults().withTls(Config.Tls.DISABLED).withAllowUnix(true);
    }

    private static byte[] content(int length) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (byte) (i * 31 + 7);
        }
        return out;
    }

    /** One {@code kXR_status} frame carrying {@code pages} after itself. */
    private static MockXrootd.Reply frame(int responseType, byte[] pages) {
        return MockXrootd.Reply.status(XrdConst.kXR_pgread, responseType, new byte[0], pages);
    }

    private static MockXrootd serving(MockXrootd.Handler pgread) throws IOException {
        MockXrootd server = new MockXrootd();
        server.on(XrdConst.kXR_open, MockXrootd.answering(request ->
                        MockXrootd.Reply.ok(new WBuf().raw(HANDLE)
                                .i32(PAGE).text("adlr", false)
                                .raw(MockXrootd.statLine("id", 0, 0, 7))
                                .bytes())))
                .on(XrdConst.kXR_pgread, pgread);
        return server;
    }

    @Test
    void readsPagesBackAndCheckTheirChecksums() throws IOException {
        byte[] content = content(2 * PAGE + 11);
        try (MockXrootd server = serving(MockXrootd.answering(request ->
                        frame(XrdConst.kXR_FinalResult, PagedIo.packPages(0, content))));
             XrdClient client = new XrdClient(config());
             XrdFile file = client.open(server.url("/data/f"))) {
            assertArrayEquals(content, file.pgRead(0, content.length));
        }
    }

    /** The pages of {@code content} from {@code from} to {@code to}, framed
     *  at the file offset they belong to. */
    private static byte[] pages(byte[] content, int from, int to) {
        return PagedIo.packPages(from, Arrays.copyOfRange(content, from, to));
    }

    @Test
    void putsSeveralFramesBackTogether() throws IOException {
        // A server may answer one request with several frames; only the last
        // is final, and the pages run on from where the one before stopped.
        byte[] content = content(3 * PAGE);
        try (MockXrootd server = serving(request -> List.of(
                        frame(XrdConst.kXR_PartialResult, pages(content, 0, PAGE)),
                        frame(XrdConst.kXR_PartialResult, pages(content, PAGE, 2 * PAGE)),
                        frame(XrdConst.kXR_FinalResult,
                                pages(content, 2 * PAGE, content.length))));
             XrdClient client = new XrdClient(config());
             XrdFile file = client.open(server.url("/data/f"))) {
            assertArrayEquals(content, file.pgRead(0, content.length));
        }
    }

    @Test
    void readsFromAnOffsetThatIsNotAPageBoundary() throws IOException {
        // The first page of an unaligned read is short, running only to the
        // next boundary, so an implementation that assumes 4096 throughout
        // reassembles the rest at the wrong offsets.
        byte[] content = content(PAGE + 100);
        long start = PAGE - 100;
        try (MockXrootd server = serving(MockXrootd.answering(request ->
                        frame(XrdConst.kXR_FinalResult, PagedIo.packPages(start, content))));
             XrdClient client = new XrdClient(config());
             XrdFile file = client.open(server.url("/data/f"))) {
            assertArrayEquals(content, file.pgRead(start, content.length));
        }
    }

    @Test
    void refusesAPageThatDoesNotMatchItsChecksum() throws IOException {
        byte[] content = content(2 * PAGE);
        byte[] framed = PagedIo.packPages(0, content);
        framed[4 + PAGE + 4] ^= 0x40;               // one bit of the second page
        try (MockXrootd server = serving(MockXrootd.answering(request ->
                        frame(XrdConst.kXR_FinalResult, framed)));
             XrdClient client = new XrdClient(config());
             XrdFile file = client.open(server.url("/data/f"))) {
            XrdProtocolException failure = assertThrows(XrdProtocolException.class,
                    () -> file.pgRead(0, content.length));
            assertTrue(failure.getMessage().contains("checksum mismatch"), failure.getMessage());
        }
    }
}

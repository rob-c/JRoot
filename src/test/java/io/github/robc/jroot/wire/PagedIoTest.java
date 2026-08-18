package io.github.robc.jroot.wire;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Random;

import org.junit.jupiter.api.Test;

import io.github.robc.jroot.XrdProtocolException;

/** Paged I/O framing: 4 KiB pages, each behind its CRC32C. */
class PagedIoTest {

    private static final int PAGE = XrdConst.kXR_pgPageSZ;

    private static byte[] data(int length) {
        byte[] out = new byte[length];
        new Random(length).nextBytes(out);
        return out;
    }

    @Test
    void endsTheFirstPageAtThePageBoundary() {
        assertEquals(PAGE, PagedIo.firstPageLength(0, PAGE * 3));
        assertEquals(PAGE - 100, PagedIo.firstPageLength(100, PAGE * 3));
        assertEquals(10, PagedIo.firstPageLength(100, 10), "a short read stays short");
        assertEquals(PAGE, PagedIo.firstPageLength(PAGE * 7, PAGE));
    }

    @Test
    void countsFourBytesOfChecksumPerPage() {
        assertEquals(0, PagedIo.framedLength(0, 0));
        assertEquals(4 + 10, PagedIo.framedLength(0, 10));
        assertEquals(4 + PAGE, PagedIo.framedLength(0, PAGE));
        assertEquals(8 + PAGE + 1, PagedIo.framedLength(0, PAGE + 1));
        // Starting one byte in makes the first page short, so the same
        // payload needs one page more.
        assertEquals(8 + PAGE, PagedIo.framedLength(1, PAGE));
    }

    @Test
    void roundTripsAnAlignedTransfer() {
        byte[] data = data(PAGE * 2 + 17);
        byte[] framed = PagedIo.packPages(0, data);
        assertEquals(PagedIo.framedLength(0, data.length), framed.length);
        assertArrayEquals(data, PagedIo.unpackPages(0, framed));
    }

    @Test
    void roundTripsAnUnalignedTransfer() {
        byte[] data = data(PAGE + 500);
        byte[] framed = PagedIo.packPages(1000, data);
        assertEquals(PagedIo.framedLength(1000, data.length), framed.length);
        assertArrayEquals(data, PagedIo.unpackPages(1000, framed));
    }

    @Test
    void roundTripsSomethingSmallerThanAPage() {
        byte[] data = data(7);
        assertArrayEquals(data, PagedIo.unpackPages(0, PagedIo.packPages(0, data)));
        assertEquals(0, PagedIo.packPages(0, new byte[0]).length);
        assertEquals(0, PagedIo.unpackPages(0, new byte[0]).length);
    }

    @Test
    void refusesAPageWhoseChecksumDoesNotMatch() {
        byte[] framed = PagedIo.packPages(0, data(PAGE + 64));
        framed[framed.length - 1] ^= 0xFF;           // corrupt the last page
        XrdProtocolException failure = assertThrows(XrdProtocolException.class,
                () -> PagedIo.unpackPages(0, framed));
        assertTrue(failure.getMessage().contains("page 1"),
                "the message should name the page: " + failure.getMessage());
    }
}

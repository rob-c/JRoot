package io.github.robc.jroot.wire;

import java.util.zip.CRC32C;

import io.github.robc.jroot.XrdProtocolException;

/**
 * The paged-I/O framing shared by {@code kXR_pgread} and {@code kXR_pgwrite}:
 * data travels as 4 KiB pages, each preceded by its CRC32C as a big-endian
 * u32. The first page of an unaligned transfer is short — it runs from the
 * requested offset to the next page boundary — and the last page holds
 * whatever remains, so only interior pages are guaranteed full-size.
 */
public final class PagedIo {

    private PagedIo() {}

    private static long crc(byte[] data, int off, int len) {
        CRC32C c = new CRC32C();
        c.update(data, off, len);
        return c.getValue();
    }

    /** Length of the first page of a transfer starting at {@code offset}. */
    public static int firstPageLength(long offset, int total) {
        int first = XrdConst.kXR_pgPageSZ - (int) (offset % XrdConst.kXR_pgPageSZ);
        return Math.min(first, total);
    }

    /** The on-wire size of {@code dataLength} bytes framed as pages. */
    public static int framedLength(long offset, int dataLength) {
        if (dataLength == 0) {
            return 0;
        }
        int first = firstPageLength(offset, dataLength);
        int pages = 1 + (dataLength - first + XrdConst.kXR_pgPageSZ - 1) / XrdConst.kXR_pgPageSZ;
        return dataLength + 4 * pages;
    }

    /** Frame {@code data} written at {@code offset} into checksummed pages. */
    public static byte[] packPages(long offset, byte[] data) {
        WBuf w = new WBuf();
        int pos = 0;
        int pageLen = firstPageLength(offset, data.length);
        while (pos < data.length) {
            w.u32(crc(data, pos, pageLen));
            w.raw(data, pos, pageLen);
            pos += pageLen;
            pageLen = Math.min(XrdConst.kXR_pgPageSZ, data.length - pos);
        }
        return w.bytes();
    }

    /**
     * Strip and verify the page framing of a {@code kXR_pgread} reply for a
     * read that started at {@code offset}. A checksum mismatch throws: the
     * protocol's retry machinery (pgread with page correction) is not worth
     * its complexity for a client that can simply re-issue the read.
     */
    public static byte[] unpackPages(long offset, byte[] framed) {
        if (framed.length == 0) {
            return framed;
        }
        RBuf r = new RBuf(framed, "kXR_pgread pages");
        // Every page costs 4 header bytes, so the data cannot exceed this.
        WBuf out = new WBuf();
        int pageLen = XrdConst.kXR_pgPageSZ - (int) (offset % XrdConst.kXR_pgPageSZ);
        int page = 0;
        while (r.remaining() > 0) {
            long expected = r.u32();
            byte[] chunk = r.bytes(Math.min(pageLen, r.remaining()));
            long actual = crc(chunk, 0, chunk.length);
            if (actual != expected) {
                throw new XrdProtocolException(String.format(
                        "kXR_pgread page %d checksum mismatch: computed %08x, server sent %08x",
                        page, actual, expected));
            }
            out.raw(chunk);
            pageLen = XrdConst.kXR_pgPageSZ;
            page++;
        }
        return out.bytes();
    }
}

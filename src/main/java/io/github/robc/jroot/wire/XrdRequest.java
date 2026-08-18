package io.github.robc.jroot.wire;

import io.github.robc.jroot.XrdProtocolException;

/**
 * Base of every client request. The wire frame is the 24-byte
 * {@code ClientRequestHdr} — streamid[2] requestid[2] params[16] dlen[4] —
 * followed by {@code dlen} payload bytes. Subclasses set {@link #opcode()},
 * write exactly 16 parameter bytes in {@link #params}, and supply the payload.
 */
public abstract class XrdRequest {

    /** The 20-byte client hello: three zero words, then 4, then ROOTD_PQ. */
    public static final byte[] HANDSHAKE = new WBuf()
            .zeros(12).i32(4).i32(XrdConst.ROOTD_PQ).bytes();

    public abstract int opcode();

    /** Whether a security level at or above standard requires a
     *  {@code kXR_sigver} prefix for this request. */
    public boolean signed() {
        return false;
    }

    /**
     * The data path this request names, or 0 for the control link. Only the
     * bulk requests carry one, and where the byte sits differs per opcode —
     * a {@code kXR_read} puts it in an optional payload, a {@code kXR_write}
     * in its parameters — which is why the value is declared here and
     * written by each encoder.
     */
    public int pathId() {
        return 0;
    }

    /** Write the 16 parameter bytes (header offsets 4..19). Default: all zero. */
    protected void params(WBuf w) {
        w.zeros(16);
    }

    /** Bytes after the header, counted in {@code dlen}, sent on the link the
     *  request itself travels. */
    protected byte[] payload() {
        return EMPTY;
    }

    /**
     * Bytes counted in {@code dlen} but sent down the data path this request
     * names rather than on the control link. Only {@code kXR_write} and
     * {@code kXR_pgwrite} have any: the server reads the header, learns from
     * {@code dlen} how much data to expect, and takes it off the bound path.
     */
    public byte[] pathData() {
        return EMPTY;
    }

    /**
     * Bytes streamed after the frame that {@code dlen} does not count.
     * Only {@code kXR_writev} has one: the server sizes its descriptor block
     * from {@code dlen} and then reads the data that follows, so counting
     * the data would make the descriptors unparseable.
     */
    protected byte[] trailer() {
        return EMPTY;
    }

    private static final byte[] EMPTY = new byte[0];

    /**
     * The whole request as one contiguous frame. This is the form a single
     * link carries, and the form a signature covers — {@code kXR_sigver}
     * hashes the header and the {@code dlen} bytes after it, wherever those
     * bytes actually travel.
     */
    public final byte[] encode(int streamId) {
        return concat(frameHeader(streamId), payload(), pathData(), trailer());
    }

    /** What the control link carries when the data goes down a path: the
     *  same frame without the bytes {@link #pathData()} claims. */
    public final byte[] controlFrame(int streamId) {
        return concat(frameHeader(streamId), payload(), EMPTY, trailer());
    }

    /**
     * The 24-byte header alone. {@code dlen} counts the payload and the path
     * data together, so a server reads the same number of bytes whether they
     * arrive on one link or two.
     */
    public final byte[] frameHeader(int streamId) {
        WBuf pw = new WBuf();
        params(pw);
        if (pw.size() != 16) {
            throw new XrdProtocolException(
                    getClass().getSimpleName() + ".params wrote " + pw.size()
                            + " bytes, expected 16");
        }
        return new WBuf()
                .u16(streamId)
                .u16(opcode())
                .raw(pw.bytes())
                .i32(payload().length + pathData().length)
                .bytes();
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int at = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, at, part.length);
            at += part.length;
        }
        return out;
    }

    @Override
    public String toString() {
        return XrdConst.requestName(opcode());
    }
}

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

    /** Write the 16 parameter bytes (header offsets 4..19). Default: all zero. */
    protected void params(WBuf w) {
        w.zeros(16);
    }

    /** Bytes after the header, counted in {@code dlen}. */
    protected byte[] payload() {
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

    /** Serialise this request into a complete wire frame for {@code streamId}. */
    public final byte[] encode(int streamId) {
        WBuf pw = new WBuf();
        params(pw);
        if (pw.size() != 16) {
            throw new XrdProtocolException(
                    getClass().getSimpleName() + ".params wrote " + pw.size()
                            + " bytes, expected 16");
        }
        byte[] body = payload();
        byte[] tail = trailer();
        return new WBuf()
                .u16(streamId)
                .u16(opcode())
                .raw(pw.bytes())
                .i32(body.length)
                .raw(body)
                .raw(tail)
                .bytes();
    }

    @Override
    public String toString() {
        return XrdConst.requestName(opcode());
    }
}

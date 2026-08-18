package io.github.robc.jroot.wire;

import io.github.robc.jroot.XrdProtocolException;

/** The 8-byte {@code ServerResponseHdr}: streamid[2] status[2] dlen[4]. */
public record ResponseHeader(int streamId, int status, int dataLength) {

    public static ResponseHeader decode(byte[] data) {
        RBuf r = new RBuf(data, "ServerResponseHdr");
        int sid = r.u16();
        int status = r.u16();
        int dlen = r.i32();
        if (dlen < 0 || dlen > XrdConst.MAX_RESPONSE_BODY) {
            throw new XrdProtocolException(
                    "response declares a body of " + dlen + " bytes, past the "
                            + XrdConst.MAX_RESPONSE_BODY + " this client will buffer");
        }
        return new ResponseHeader(sid, status, dlen);
    }

    @Override
    public String toString() {
        return "ResponseHeader[sid=" + streamId + ", " + XrdConst.statusName(status)
                + ", dlen=" + dataLength + "]";
    }
}

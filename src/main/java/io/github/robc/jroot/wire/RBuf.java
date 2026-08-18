package io.github.robc.jroot.wire;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import io.github.robc.jroot.XrdProtocolException;

/**
 * A bounds-checked big-endian reader over a response body. Every read that
 * would run past the end raises {@link XrdProtocolException} naming the
 * structure being decoded, because a short body is a broken or hostile
 * server, not an index error.
 */
public final class RBuf {

    private final byte[] data;
    private final String what;
    private int pos;

    public RBuf(byte[] data, String what) {
        this.data = data;
        this.what = what;
    }

    private void need(int n) {
        if (n < 0 || data.length - pos < n) {
            throw new XrdProtocolException(
                    what + " is truncated: need " + n + " bytes at offset " + pos
                            + ", have " + (data.length - pos));
        }
    }

    public int u8() {
        need(1);
        return data[pos++] & 0xFF;
    }

    public int u16() {
        need(2);
        int v = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
        pos += 2;
        return v;
    }

    public int i32() {
        need(4);
        int v = ((data[pos] & 0xFF) << 24) | ((data[pos + 1] & 0xFF) << 16)
                | ((data[pos + 2] & 0xFF) << 8) | (data[pos + 3] & 0xFF);
        pos += 4;
        return v;
    }

    public long u32() {
        return i32() & 0xFFFFFFFFL;
    }

    public long i64() {
        long hi = i32() & 0xFFFFFFFFL;
        long lo = i32() & 0xFFFFFFFFL;
        return (hi << 32) | lo;
    }

    public byte[] bytes(int n) {
        need(n);
        byte[] out = Arrays.copyOfRange(data, pos, pos + n);
        pos += n;
        return out;
    }

    public void skip(int n) {
        need(n);
        pos += n;
    }

    /** UTF-8 up to a NUL or the end of the buffer; consumes the NUL. */
    public String cstring() {
        int start = pos;
        while (pos < data.length && data[pos] != 0) {
            pos++;
        }
        String s = new String(data, start, pos - start, StandardCharsets.UTF_8);
        if (pos < data.length) {
            pos++;
        }
        return s;
    }

    public byte[] rest() {
        byte[] out = Arrays.copyOfRange(data, pos, data.length);
        pos = data.length;
        return out;
    }

    public int remaining() {
        return data.length - pos;
    }
}

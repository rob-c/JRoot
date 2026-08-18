package io.github.robc.jroot.wire;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/** A growable big-endian writer; every multi-byte value on the wire is network order. */
public final class WBuf {

    private final ByteArrayOutputStream out = new ByteArrayOutputStream(64);

    public WBuf u8(int v) {
        out.write(v & 0xFF);
        return this;
    }

    public WBuf u16(int v) {
        out.write((v >>> 8) & 0xFF);
        out.write(v & 0xFF);
        return this;
    }

    public WBuf i32(int v) {
        out.write((v >>> 24) & 0xFF);
        out.write((v >>> 16) & 0xFF);
        out.write((v >>> 8) & 0xFF);
        out.write(v & 0xFF);
        return this;
    }

    public WBuf u32(long v) {
        return i32((int) v);
    }

    public WBuf i64(long v) {
        i32((int) (v >>> 32));
        i32((int) v);
        return this;
    }

    public WBuf zeros(int n) {
        for (int i = 0; i < n; i++) {
            out.write(0);
        }
        return this;
    }

    public WBuf raw(byte[] data) {
        out.writeBytes(data);
        return this;
    }

    public WBuf raw(byte[] data, int off, int len) {
        out.write(data, off, len);
        return this;
    }

    /** UTF-8 text, optionally NUL-terminated. */
    public WBuf text(String s, boolean nul) {
        out.writeBytes(s.getBytes(StandardCharsets.UTF_8));
        if (nul) {
            out.write(0);
        }
        return this;
    }

    /**
     * Exactly {@code width} bytes: {@code data} truncated or NUL-padded.
     * This is how fixed fields like the 8-byte username and the 4-byte
     * fhandle are laid down.
     */
    public WBuf padded(byte[] data, int width) {
        int n = Math.min(data.length, width);
        out.write(data, 0, n);
        return zeros(width - n);
    }

    public WBuf padded(String s, int width) {
        return padded(s.getBytes(StandardCharsets.UTF_8), width);
    }

    public int size() {
        return out.size();
    }

    public byte[] bytes() {
        return out.toByteArray();
    }
}

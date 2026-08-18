package io.github.robc.jroot.auth;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import io.github.robc.jroot.XrdAuthException;
import io.github.robc.jroot.wire.WBuf;

/**
 * XrdSut's bucket buffer, the frame every GSI message travels in: the
 * NUL-terminated name {@code "gsi"}, a big-endian step code, then
 * type-length-value buckets closed by a zero type.
 */
public final class GsiMessage {

    private GsiMessage() {}

    // Steps: server messages are kXGS_*, client messages kXGC_*.
    public static final int STEP_SERVER_INIT = 2000;
    public static final int STEP_SERVER_CERT = 2001;
    public static final int STEP_SERVER_PXYREQ = 2002;
    public static final int STEP_CLIENT_CERTREQ = 1000;
    public static final int STEP_CLIENT_CERT = 1001;
    public static final int STEP_CLIENT_SIGPXY = 1002;

    // XrdSutBucket type codes.
    public static final int BUCKET_NONE = 0;
    public static final int BUCKET_CRYPTOMOD = 3000;
    public static final int BUCKET_MAIN = 3001;
    public static final int BUCKET_PUK = 3004;
    public static final int BUCKET_CIPHER = 3005;
    public static final int BUCKET_RTAG = 3006;
    public static final int BUCKET_SIGNED_RTAG = 3007;
    public static final int BUCKET_USER = 3008;
    public static final int BUCKET_VERSION = 3014;
    public static final int BUCKET_CLNT_OPTS = 3019;
    public static final int BUCKET_X509 = 3022;
    public static final int BUCKET_ISSUER_HASH = 3023;
    public static final int BUCKET_X509_REQ = 3024;
    public static final int BUCKET_CIPHER_ALG = 3025;
    public static final int BUCKET_MD_ALG = 3026;

    /** One type-length-value element of a GSI message. */
    public record Bucket(int type, byte[] data) {

        public static Bucket of(int type, String text) {
            return new Bucket(type, text.getBytes(StandardCharsets.US_ASCII));
        }

        public static Bucket of(int type, int value) {
            return new Bucket(type, new WBuf().i32(value).bytes());
        }

        @Override
        public String toString() {
            return "Bucket[type=" + type + ", len=" + data.length + "]";
        }
    }

    /** A decoded message: its step code and its buckets, in order. */
    public record Decoded(int step, List<Bucket> buckets) {

        /** The first bucket of {@code type}, or {@code null}. */
        public byte[] find(int type) {
            for (Bucket bucket : buckets) {
                if (bucket.type() == type) {
                    return bucket.data();
                }
            }
            return null;
        }
    }

    public static byte[] encode(int step, List<Bucket> buckets) {
        WBuf w = new WBuf().text("gsi", true).i32(step);
        for (Bucket bucket : buckets) {
            w.i32(bucket.type()).i32(bucket.data().length).raw(bucket.data());
        }
        return w.i32(BUCKET_NONE).bytes();
    }

    public static Decoded decode(byte[] data) {
        int end = 0;
        while (end < data.length && data[end] != 0) {
            end++;
        }
        if (end >= data.length) {
            throw new XrdAuthException("GSI message has no protocol name");
        }
        int pos = end + 1;
        if (pos + 4 > data.length) {
            throw new XrdAuthException("GSI message is too short for a step code");
        }
        int step = int32(data, pos);
        pos += 4;
        List<Bucket> buckets = new ArrayList<>();
        while (pos + 4 <= data.length) {
            int type = int32(data, pos);
            pos += 4;
            if (type == BUCKET_NONE) {
                break;
            }
            if (pos + 4 > data.length) {
                throw new XrdAuthException("GSI bucket " + type + " has a truncated length");
            }
            int length = int32(data, pos);
            pos += 4;
            if (length < 0 || length > data.length - pos) {
                throw new XrdAuthException("GSI bucket " + type + " claims " + length
                        + " bytes, " + (data.length - pos) + " available");
            }
            byte[] value = new byte[length];
            System.arraycopy(data, pos, value, 0, length);
            buckets.add(new Bucket(type, value));
            pos += length;
        }
        return new Decoded(step, buckets);
    }

    /** The first bucket of {@code type} in an encoded message, or {@code null}. */
    public static byte[] find(byte[] message, int type) {
        try {
            return decode(message).find(type);
        } catch (XrdAuthException e) {
            return null;
        }
    }

    private static int int32(byte[] data, int at) {
        return ((data[at] & 0xFF) << 24) | ((data[at + 1] & 0xFF) << 16)
                | ((data[at + 2] & 0xFF) << 8) | (data[at + 3] & 0xFF);
    }
}

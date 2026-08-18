package io.github.robc.jroot.crypto;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

import io.github.robc.jroot.XrdAuthException;

/**
 * The writing half of {@link Der}: enough encoding to build a certificate.
 *
 * <p>Only X.509 delegation needs this. When a server asks a client to sign a
 * proxy for it, the client is issuing a certificate, and a certificate is a
 * DER structure the JDK will happily read but has no public API to write.
 * The subset here is exactly what {@link ProxySigner} puts on the wire.
 */
public final class DerWriter {

    private DerWriter() {}

    private static final DateTimeFormatter UTC_TIME =
            DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'", Locale.ROOT).withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter GENERALIZED_TIME =
            DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'", Locale.ROOT).withZone(ZoneOffset.UTC);

    /** {@code UTCTime} runs out in 2050; after that X.509 says to switch. */
    private static final Instant UTC_TIME_LIMIT = Instant.parse("2050-01-01T00:00:00Z");

    /** One TLV: the tag, the length in DER's own form, then the content. */
    public static byte[] tagged(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        if (content.length < 0x80) {
            out.write(content.length);
        } else {
            byte[] length = BigInteger.valueOf(content.length).toByteArray();
            int skip = length[0] == 0 ? 1 : 0;      // drop the sign byte
            out.write(0x80 | (length.length - skip));
            out.write(length, skip, length.length - skip);
        }
        out.writeBytes(content);
        return out.toByteArray();
    }

    public static byte[] sequenceOf(byte[]... parts) {
        return tagged(Der.TAG_SEQUENCE, concat(parts));
    }

    public static byte[] setOf(byte[]... parts) {
        return tagged(0x31, concat(parts));
    }

    /** A context-specific constructed element, {@code [number] { content }}. */
    public static byte[] explicit(int number, byte[] content) {
        return tagged(0xA0 | number, content);
    }

    public static byte[] integer(BigInteger value) {
        return tagged(Der.TAG_INTEGER, value.toByteArray());
    }

    public static byte[] integer(long value) {
        return integer(BigInteger.valueOf(value));
    }

    public static byte[] octetString(byte[] value) {
        return tagged(Der.TAG_OCTET_STRING, value);
    }

    /** A BIT STRING whose last content byte has {@code unused} spare bits. */
    public static byte[] bitString(byte[] value, int unused) {
        byte[] content = new byte[value.length + 1];
        content[0] = (byte) unused;
        System.arraycopy(value, 0, content, 1, value.length);
        return tagged(Der.TAG_BIT_STRING, content);
    }

    public static byte[] bool(boolean value) {
        return tagged(0x01, new byte[] {(byte) (value ? 0xFF : 0x00)});
    }

    public static byte[] printableString(String text) {
        return tagged(0x13, text.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    public static byte[] nullValue() {
        return tagged(0x05, new byte[0]);
    }

    /**
     * A time, in the form X.509 requires for the year it falls in: two-digit
     * {@code UTCTime} before 2050 and four-digit {@code GeneralizedTime}
     * after, both to the second and always in UTC.
     */
    public static byte[] time(Instant when) {
        return when.isBefore(UTC_TIME_LIMIT)
                ? tagged(0x17, UTC_TIME.format(when)
                        .getBytes(java.nio.charset.StandardCharsets.US_ASCII))
                : tagged(0x18, GENERALIZED_TIME.format(when)
                        .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    /** An OBJECT IDENTIFIER from its dotted-decimal form. */
    public static byte[] oid(String dotted) {
        String[] arcs = dotted.split("\\.");
        if (arcs.length < 2) {
            throw new XrdAuthException("not an object identifier: " + dotted);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // The first two arcs share one byte: 40 * first + second.
        out.write(Integer.parseInt(arcs[0]) * 40 + Integer.parseInt(arcs[1]));
        for (int i = 2; i < arcs.length; i++) {
            base128(out, Long.parseLong(arcs[i]));
        }
        return tagged(Der.TAG_OID, out.toByteArray());
    }

    /** Base-128, high bit set on every byte but the last. */
    private static void base128(ByteArrayOutputStream out, long arc) {
        int width = 1;
        for (long rest = arc >>> 7; rest > 0; rest >>>= 7) {
            width++;
        }
        for (int shift = (width - 1) * 7; shift >= 0; shift -= 7) {
            int b = (int) ((arc >>> shift) & 0x7F);
            out.write(shift == 0 ? b : b | 0x80);
        }
    }

    public static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }
}

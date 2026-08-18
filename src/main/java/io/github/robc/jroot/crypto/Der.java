package io.github.robc.jroot.crypto;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Just enough DER to read the structures GSI puts in front of this client:
 * {@code DHParameter} and the two shapes an RSA private key comes in. The
 * JDK reads X.509 and PKCS#8 itself; PKCS#1 ({@code RSA PRIVATE KEY}) it
 * does not, and that is what {@code grid-proxy-init} writes.
 */
public final class Der {

    private Der() {}

    public static final int TAG_INTEGER = 0x02;
    public static final int TAG_BIT_STRING = 0x03;
    public static final int TAG_OCTET_STRING = 0x04;
    public static final int TAG_OID = 0x06;
    public static final int TAG_SEQUENCE = 0x30;

    /** Thrown for anything malformed; never carries attacker-supplied bytes. */
    public static final class DerException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public DerException(String message) {
            super(message);
        }
    }

    /** One TLV. {@code value} is the content octets, constructed or not. */
    public record Element(int tag, byte[] value) {

        public boolean isConstructed() {
            return (tag & 0x20) != 0;
        }

        /** The elements nested inside a constructed value. */
        public List<Element> children() {
            if (!isConstructed()) {
                throw new DerException(
                        String.format("tag 0x%02x is primitive and has no children", tag));
            }
            List<Element> out = new ArrayList<>();
            int pos = 0;
            while (pos < value.length) {
                Parsed p = parseAt(value, pos);
                out.add(p.element());
                pos = p.end();
            }
            return out;
        }

        public BigInteger integer() {
            if (tag != TAG_INTEGER) {
                throw new DerException(String.format("tag 0x%02x is not an INTEGER", tag));
            }
            if (value.length == 0) {
                throw new DerException("INTEGER has no content octets");
            }
            return new BigInteger(value);
        }

        /** Dotted-decimal form of an OBJECT IDENTIFIER. */
        public String oid() {
            if (tag != TAG_OID || value.length == 0) {
                throw new DerException(String.format("tag 0x%02x is not an OID", tag));
            }
            StringBuilder out = new StringBuilder();
            int first = value[0] & 0xFF;
            out.append(Math.min(first / 40, 2)).append('.').append(first - 40 * Math.min(first / 40, 2));
            long arc = 0;
            for (int i = 1; i < value.length; i++) {
                int b = value[i] & 0xFF;
                arc = (arc << 7) | (b & 0x7F);
                if ((b & 0x80) == 0) {
                    out.append('.').append(arc);
                    arc = 0;
                }
            }
            return out.toString();
        }
    }

    private record Parsed(Element element, int end) {}

    private static Parsed parseAt(byte[] data, int start) {
        if (start + 2 > data.length) {
            throw new DerException("DER element is truncated at offset " + start);
        }
        int tag = data[start] & 0xFF;
        int pos = start + 1;
        if ((tag & 0x1F) == 0x1F) {
            throw new DerException("high-tag-number DER elements are not supported");
        }
        int length = data[pos++] & 0xFF;
        if (length == 0x80) {
            throw new DerException("indefinite-length DER is not valid");
        }
        if (length > 0x80) {
            int count = length & 0x7F;
            if (count > 4 || pos + count > data.length) {
                throw new DerException("DER length at offset " + start + " is unreadable");
            }
            length = 0;
            for (int i = 0; i < count; i++) {
                length = (length << 8) | (data[pos++] & 0xFF);
            }
            if (length < 0) {
                throw new DerException("DER length at offset " + start + " overflows");
            }
        }
        if (length > data.length - pos) {
            throw new DerException("DER element at offset " + start + " claims " + length
                    + " bytes, " + (data.length - pos) + " available");
        }
        byte[] value = new byte[length];
        System.arraycopy(data, pos, value, 0, length);
        return new Parsed(new Element(tag, value), pos + length);
    }

    /** The first element of {@code data}; trailing bytes are ignored. */
    public static Element parse(byte[] data) {
        return parseAt(data, 0).element();
    }

    /** The children of a SEQUENCE, refusing anything else. */
    public static List<Element> sequence(byte[] data) {
        Element element = parse(data);
        if (element.tag() != TAG_SEQUENCE) {
            throw new DerException(
                    String.format("expected a SEQUENCE, found tag 0x%02x", element.tag()));
        }
        return element.children();
    }
}

package io.github.robc.jroot.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.List;

import io.github.robc.jroot.XrdAuthException;
import io.github.robc.jroot.crypto.Der.Element;

/**
 * Loading RSA private keys, and the one signature GSI asks of them.
 *
 * <p>The signature is {@link java.security.Signature} in spirit only: the
 * GSI proof of possession is EMSA-PKCS1-v1_5 padding around the <em>raw
 * message</em>, with no DigestInfo wrapper, because that is what
 * {@code XrdCryptosslRSA::EncryptPrivate} produces. No JCA signature
 * algorithm names that construction, so the padding is laid out here and
 * the exponentiation is {@link BigInteger#modPow}. It runs once per
 * connection over a random tag the client itself chose, which is why the
 * absence of blinding is acceptable here and would not be on a data path.
 */
public final class RsaKeys {

    private RsaKeys() {}

    private static final String RSA_OID = "1.2.840.113549.1.1.1";

    /**
     * Load an RSA private key from PEM or bare DER, accepting PKCS#1
     * ({@code RSA PRIVATE KEY}) and unencrypted PKCS#8 ({@code PRIVATE KEY}).
     * An encrypted key is refused by name, because the fix is to decrypt it.
     */
    public static RSAPrivateKey loadPrivateKey(byte[] data) {
        List<Pem.Block> blocks = Pem.blocks(data);
        if (blocks.isEmpty()) {
            return fromDer(data);
        }
        for (Pem.Block block : blocks) {
            switch (block.label()) {
                case "ENCRYPTED PRIVATE KEY" ->
                        throw new XrdAuthException("the private key is encrypted; decrypt it first");
                case "RSA PRIVATE KEY", "PRIVATE KEY" -> {
                    return fromDer(block.der());
                }
                default -> { }
            }
        }
        throw new XrdAuthException("no RSA private key in the PEM given");
    }

    private static RSAPrivateKey fromDer(byte[] der) {
        List<Element> fields;
        try {
            fields = Der.sequence(der);
        } catch (Der.DerException e) {
            throw new XrdAuthException("unreadable private key: " + e.getMessage(), e);
        }
        // PKCS#8 wraps the PKCS#1 body: version, AlgorithmIdentifier, OCTET STRING.
        if (fields.size() >= 3 && fields.get(1).tag() == Der.TAG_SEQUENCE
                && fields.get(2).tag() == Der.TAG_OCTET_STRING) {
            String algorithm = fields.get(1).children().get(0).oid();
            if (!RSA_OID.equals(algorithm)) {
                throw new XrdAuthException("private key is " + algorithm + ", not RSA");
            }
            return keyFactory(new PKCS8EncodedKeySpec(der));
        }
        return fromPkcs1(fields);
    }

    /** {@code RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, dp, dq, qInv }}. */
    private static RSAPrivateKey fromPkcs1(List<Element> fields) {
        if (fields.size() < 9) {
            throw new XrdAuthException("PKCS#1 private key has " + fields.size()
                    + " fields, expected 9");
        }
        BigInteger[] v = new BigInteger[9];
        for (int i = 0; i < 9; i++) {
            v[i] = fields.get(i).integer();
        }
        if (v[0].signum() != 0) {
            throw new XrdAuthException("multi-prime RSA (version " + v[0] + ") is not supported");
        }
        return keyFactory(new RSAPrivateCrtKeySpec(v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8]));
    }

    private static RSAPrivateKey keyFactory(java.security.spec.KeySpec spec) {
        try {
            PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(spec);
            if (!(key instanceof RSAPrivateKey rsa)) {
                throw new XrdAuthException("the key factory returned a " + key.getAlgorithm()
                        + " key, not RSA");
            }
            return rsa;
        } catch (GeneralSecurityException e) {
            throw new XrdAuthException("unusable RSA private key: " + e.getMessage(), e);
        }
    }

    /** The modulus length in bytes — the size of every signature block. */
    public static int size(RSAPrivateKey key) {
        return (key.getModulus().bitLength() + 7) / 8;
    }

    /**
     * PKCS#1 v1.5 signature over {@code message} itself: the block is
     * {@code 00 01 FF..FF 00 || message}, encrypted under the private key.
     */
    public static byte[] signRaw(RSAPrivateKey key, byte[] message) {
        int size = size(key);
        if (message.length + 11 > size) {
            throw new XrdAuthException("a message of " + message.length
                    + " bytes does not fit a " + size + "-byte RSA key");
        }
        byte[] block = new byte[size];
        block[0] = 0x00;
        block[1] = 0x01;
        int pad = size - message.length - 3;
        for (int i = 0; i < pad; i++) {
            block[2 + i] = (byte) 0xFF;
        }
        block[2 + pad] = 0x00;
        System.arraycopy(message, 0, block, size - message.length, message.length);

        BigInteger signature = new BigInteger(1, block)
                .modPow(key.getPrivateExponent(), key.getModulus());
        byte[] raw = signature.toByteArray();
        byte[] out = new byte[size];
        // BigInteger drops leading zeros and may add a sign byte; the wire
        // wants exactly one modulus-length block, right-aligned.
        if (raw.length > size) {
            System.arraycopy(raw, raw.length - size, out, 0, size);
        } else {
            System.arraycopy(raw, 0, out, size - raw.length, raw.length);
        }
        return out;
    }
}

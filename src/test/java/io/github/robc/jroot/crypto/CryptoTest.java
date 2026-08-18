package io.github.robc.jroot.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import io.github.robc.jroot.XrdException;

/** The crypto primitives GSI needs, checked against the JDK's own. */
class CryptoTest {

    private static KeyPair keys;

    @BeforeAll
    static void generate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keys = generator.generateKeyPair();
    }

    // -----------------------------------------------------------------
    // PEM
    // -----------------------------------------------------------------

    @Test
    void roundTripsAPemBlock() {
        byte[] der = keys.getPrivate().getEncoded();
        byte[] pem = Pem.encode("PRIVATE KEY", der);
        String text = new String(pem, StandardCharsets.US_ASCII);
        assertTrue(text.startsWith("-----BEGIN PRIVATE KEY-----\n"));
        assertTrue(text.trim().endsWith("-----END PRIVATE KEY-----"));
        List<Pem.Block> blocks = Pem.blocks(pem);
        assertEquals(1, blocks.size());
        assertEquals("PRIVATE KEY", blocks.get(0).label());
        assertArrayEquals(der, blocks.get(0).der());
    }

    @Test
    void readsEveryBlockOfAProxyChainInOrder() {
        String file = "leading junk a proxy file always has\n"
                + pem("CERTIFICATE", new byte[] {1, 2, 3})
                + "Bag Attributes: ignored\n"
                + pem("RSA PRIVATE KEY", new byte[] {4, 5, 6})
                + pem("CERTIFICATE", new byte[] {7, 8, 9});
        List<Pem.Block> blocks = Pem.blocks(file.getBytes(StandardCharsets.US_ASCII));
        assertEquals(List.of("CERTIFICATE", "RSA PRIVATE KEY", "CERTIFICATE"),
                blocks.stream().map(Pem.Block::label).toList());
        List<byte[]> certificates =
                Pem.blocks(file.getBytes(StandardCharsets.US_ASCII), "CERTIFICATE");
        assertEquals(2, certificates.size());
        assertArrayEquals(new byte[] {1, 2, 3}, certificates.get(0));
        assertArrayEquals(new byte[] {7, 8, 9}, certificates.get(1));
    }

    @Test
    void findsNoBlocksInSomethingThatIsNotPem() {
        assertTrue(Pem.blocks("not a certificate".getBytes(StandardCharsets.US_ASCII))
                .isEmpty());
    }

    // -----------------------------------------------------------------
    // DER
    // -----------------------------------------------------------------

    @Test
    void walksADerSequence() {
        // SEQUENCE { INTEGER 42, OID 1.2.840.113549.1.1.1 }
        byte[] der = {0x30, 0x0E,
                0x02, 0x01, 42,
                0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7,
                0x0D, 0x01, 0x01, 0x01};
        Der.Element root = Der.parse(der);
        assertTrue(root.isConstructed());
        List<Der.Element> children = root.children();
        assertEquals(2, children.size());
        assertEquals(BigInteger.valueOf(42), children.get(0).integer());
        assertEquals("1.2.840.113549.1.1.1", children.get(1).oid());
        assertEquals(2, Der.sequence(der).size());
    }

    @Test
    void readsALongFormLength() {
        byte[] value = new byte[200];
        Arrays.fill(value, (byte) 0x5A);
        byte[] der = new byte[204];
        der[0] = 0x04;                       // OCTET STRING
        der[1] = (byte) 0x81;                // one length byte follows
        der[2] = (byte) 200;
        System.arraycopy(value, 0, der, 3, 200);
        Der.Element element = Der.parse(Arrays.copyOf(der, 203));
        assertEquals(0x04, element.tag());
        assertArrayEquals(value, element.value());
    }

    @Test
    void refusesDerThatLiesAboutItsLength() {
        assertThrows(Der.DerException.class,
                () -> Der.parse(new byte[] {0x04, 0x7F, 1, 2, 3}));
        assertThrows(Der.DerException.class, () -> Der.parse(new byte[] {0x04}));
        assertThrows(Der.DerException.class,
                () -> Der.parse(new byte[] {0x02, 0x01, 1}).children());
    }

    // -----------------------------------------------------------------
    // RSA
    // -----------------------------------------------------------------

    @Test
    void loadsAPkcs8PrivateKey() {
        RSAPrivateKey loaded = RsaKeys.loadPrivateKey(
                Pem.encode("PRIVATE KEY", keys.getPrivate().getEncoded()));
        assertEquals(((RSAPrivateKey) keys.getPrivate()).getModulus(), loaded.getModulus());
        assertEquals(256, RsaKeys.size(loaded));
    }

    @Test
    void loadsAPkcs1PrivateKey() {
        RSAPrivateCrtKey key = (RSAPrivateCrtKey) keys.getPrivate();
        byte[] pkcs1 = pkcs1(key);
        RSAPrivateKey loaded = RsaKeys.loadPrivateKey(Pem.encode("RSA PRIVATE KEY", pkcs1));
        assertEquals(key.getModulus(), loaded.getModulus());
        assertEquals(key.getPrivateExponent(), loaded.getPrivateExponent());
    }

    @Test
    void loadsAKeyFromRawDerToo() {
        assertEquals(((RSAPrivateKey) keys.getPrivate()).getModulus(),
                RsaKeys.loadPrivateKey(keys.getPrivate().getEncoded()).getModulus());
    }

    @Test
    void refusesSomethingThatIsNotAKey() {
        assertThrows(XrdException.class,
                () -> RsaKeys.loadPrivateKey("nothing here".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void signsTheWayGsiExpects() throws Exception {
        // GSI signs the SHA-256 hash itself with PKCS#1 v1.5 padding and no
        // DigestInfo wrapper, so the JDK's NONEwithRSA must verify it.
        byte[] message = "random tag from the server".getBytes(StandardCharsets.UTF_8);
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(message);
        byte[] signature = RsaKeys.signRaw((RSAPrivateKey) keys.getPrivate(), hash);
        assertEquals(256, signature.length);
        Signature verifier = Signature.getInstance("NONEwithRSA");
        verifier.initVerify(keys.getPublic());
        verifier.update(hash);
        assertTrue(verifier.verify(signature));
    }

    // -----------------------------------------------------------------
    // AES
    // -----------------------------------------------------------------

    @Test
    void roundTripsAesCbc() {
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
        byte[] plain = "sixteen bytes!! and some more".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = Aes.cbcEncrypt(key, plain);
        assertEquals(0, encrypted.length % 16, "padded up to the block size");
        assertNotEquals(plain.length, encrypted.length);
        assertArrayEquals(plain, Aes.cbcDecrypt(key, encrypted));
    }

    @Test
    void encryptsWithAZeroIvByDefault() throws Exception {
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
        byte[] plain = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(new byte[16], Aes.zeroIv());
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new IvParameterSpec(new byte[16]));
        assertArrayEquals(cipher.doFinal(plain),
                Aes.cbcEncrypt(key, Aes.zeroIv(), plain, false));
    }

    @Test
    void refusesAnUnpaddedLengthThatIsNotABlockMultiple() {
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
        assertThrows(XrdException.class,
                () -> Aes.cbcEncrypt(key, Aes.zeroIv(), new byte[3], false));
    }

    // -----------------------------------------------------------------

    /** The PKCS#1 body of an RSA key, which is what a legacy proxy holds. */
    private static byte[] pkcs1(RSAPrivateCrtKey key) {
        WSeq seq = new WSeq();
        seq.integer(BigInteger.ZERO);
        seq.integer(key.getModulus());
        seq.integer(key.getPublicExponent());
        seq.integer(key.getPrivateExponent());
        seq.integer(key.getPrimeP());
        seq.integer(key.getPrimeQ());
        seq.integer(key.getPrimeExponentP());
        seq.integer(key.getPrimeExponentQ());
        seq.integer(key.getCrtCoefficient());
        return seq.sequence();
    }

    /** Just enough DER writing to build a key for the reader to read. */
    private static final class WSeq {
        private final java.io.ByteArrayOutputStream body =
                new java.io.ByteArrayOutputStream();

        void integer(BigInteger value) {
            byte[] bytes = value.toByteArray();
            body.write(0x02);
            length(body, bytes.length);
            body.writeBytes(bytes);
        }

        byte[] sequence() {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            out.write(0x30);
            length(out, body.size());
            out.writeBytes(body.toByteArray());
            return out.toByteArray();
        }

        private static void length(java.io.ByteArrayOutputStream out, int length) {
            if (length < 0x80) {
                out.write(length);
                return;
            }
            byte[] encoded = BigInteger.valueOf(length).toByteArray();
            int from = encoded[0] == 0 ? 1 : 0;
            out.write(0x80 | (encoded.length - from));
            out.write(encoded, from, encoded.length - from);
        }
    }

    @Test
    void isNotFooledByAnEmptyFile() {
        assertTrue(Pem.blocks(new byte[0]).isEmpty());
        assertFalse(pem("CERTIFICATE", new byte[] {1}).isEmpty());
    }

    private static String pem(String label, byte[] der) {
        return new String(Pem.encode(label, der), StandardCharsets.US_ASCII);
    }
}

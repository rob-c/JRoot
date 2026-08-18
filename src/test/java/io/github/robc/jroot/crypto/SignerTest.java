package io.github.robc.jroot.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.github.robc.jroot.wire.XrdConst;

/** {@code kXR_sigver}: which requests are signed, and what the signature is. */
class SignerTest {

    private static final byte[] KEY = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);

    private static Signer signer(int level) {
        return new Signer(KEY, level, Map.of(), false, false);
    }

    /** A request frame: header then payload, exactly as it goes on the wire. */
    private static byte[] frame(int streamId, int opcode, byte[] payload) {
        byte[] out = new byte[XrdConst.REQUEST_HDRLEN + payload.length];
        ByteBuffer buffer = ByteBuffer.wrap(out);
        buffer.putShort((short) streamId);
        buffer.putShort((short) opcode);
        buffer.position(XrdConst.REQUEST_HDRLEN - 4);
        buffer.putInt(payload.length);
        System.arraycopy(payload, 0, out, XrdConst.REQUEST_HDRLEN, payload.length);
        return out;
    }

    // -----------------------------------------------------------------
    // What gets signed
    // -----------------------------------------------------------------

    @Test
    void signsNothingBelowStandard() {
        for (int level : new int[] {XrdConst.kXR_secNone, XrdConst.kXR_secCompatible}) {
            assertFalse(Signer.isSigned(XrdConst.kXR_open, level, Map.of()));
            assertFalse(Signer.isSigned(XrdConst.kXR_rm, level, Map.of()));
        }
    }

    @Test
    void signsTheRequestsThatChangeSomethingAtStandard() {
        int level = XrdConst.kXR_secStandard;
        assertTrue(Signer.isSigned(XrdConst.kXR_open, level, Map.of()));
        assertTrue(Signer.isSigned(XrdConst.kXR_write, level, Map.of()));
        assertTrue(Signer.isSigned(XrdConst.kXR_rm, level, Map.of()));
        assertTrue(Signer.isSigned(XrdConst.kXR_chkpoint, level, Map.of()));
        assertFalse(Signer.isSigned(XrdConst.kXR_read, level, Map.of()));
        assertFalse(Signer.isSigned(XrdConst.kXR_stat, level, Map.of()));
        assertFalse(Signer.isSigned(XrdConst.kXR_close, level, Map.of()));
    }

    @Test
    void addsTheRequestsThatNameAPathAtIntense() {
        int level = XrdConst.kXR_secIntense;
        assertTrue(Signer.isSigned(XrdConst.kXR_stat, level, Map.of()));
        assertTrue(Signer.isSigned(XrdConst.kXR_dirlist, level, Map.of()));
        assertTrue(Signer.isSigned(XrdConst.kXR_locate, level, Map.of()));
        assertTrue(Signer.isSigned(XrdConst.kXR_close, level, Map.of()));
        assertTrue(Signer.isSigned(XrdConst.kXR_open, level, Map.of()));
        assertFalse(Signer.isSigned(XrdConst.kXR_read, level, Map.of()));
    }

    @Test
    void signsEverythingAtPedantic() {
        int level = XrdConst.kXR_secPedantic;
        assertTrue(Signer.isSigned(XrdConst.kXR_read, level, Map.of()));
        assertTrue(Signer.isSigned(XrdConst.kXR_ping, level, Map.of()));
        assertTrue(Signer.isSigned(XrdConst.kXR_clone, level, Map.of()));
        assertFalse(Signer.isSigned(XrdConst.kXR_1stRequest - 1, level, Map.of()),
                "not a request at all");
        assertFalse(Signer.isSigned(XrdConst.kXR_clone + 1, level, Map.of()));
    }

    @Test
    void letsTheServerOverrideEitherWay() {
        Map<Integer, Integer> exempt = Map.of(XrdConst.kXR_open, XrdConst.kXR_secNone);
        assertFalse(Signer.isSigned(XrdConst.kXR_open, XrdConst.kXR_secStandard, exempt),
                "the table says this one needs no signature after all");

        Map<Integer, Integer> pullIn = Map.of(XrdConst.kXR_read, XrdConst.kXR_secStandard);
        assertTrue(Signer.isSigned(XrdConst.kXR_read, XrdConst.kXR_secStandard, pullIn));
        assertTrue(Signer.isSigned(XrdConst.kXR_read, XrdConst.kXR_secNone, pullIn),
                "an override outranks the level it sits under");
    }

    @Test
    void signsNothingWithoutASessionKey() {
        Signer none = new Signer(new byte[0], XrdConst.kXR_secPedantic, Map.of(), false, false);
        assertFalse(none.required(XrdConst.kXR_open));
        assertNull(none.sign(frame(1, XrdConst.kXR_open, new byte[0])));
        assertTrue(signer(XrdConst.kXR_secStandard).required(XrdConst.kXR_open));
    }

    // -----------------------------------------------------------------
    // The signature itself
    // -----------------------------------------------------------------

    @Test
    void hashesTheSequenceNumberTheHeaderAndThePayload() throws Exception {
        byte[] header = new byte[XrdConst.REQUEST_HDRLEN];
        header[3] = 0x11;
        byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);

        MessageDigest expected = MessageDigest.getInstance("SHA-256");
        expected.update(ByteBuffer.allocate(8).putLong(42).array());
        expected.update(header);
        expected.update(payload);
        assertArrayEquals(expected.digest(), Signer.hash(42, header, payload, false));

        MessageDigest withoutData = MessageDigest.getInstance("SHA-256");
        withoutData.update(ByteBuffer.allocate(8).putLong(42).array());
        withoutData.update(header);
        assertArrayEquals(withoutData.digest(), Signer.hash(42, header, payload, true));
    }

    @Test
    void encryptsTheHashUnderTheSessionKey() {
        Signer signer = signer(XrdConst.kXR_secStandard);
        byte[] payload = "some arguments".getBytes(StandardCharsets.UTF_8);
        byte[] frame = frame(7, XrdConst.kXR_open, payload);

        Signer.Signature signature = signer.sign(frame);
        assertNotNull(signature);
        assertEquals(1, signature.sequence(), "the first signature is number one");
        assertFalse(signature.nodata(), "kXR_open carries arguments, not data");

        byte[] header = java.util.Arrays.copyOf(frame, XrdConst.REQUEST_HDRLEN);
        assertArrayEquals(Aes.cbcEncrypt(KEY, Signer.hash(1, header, payload, false)),
                signature.bytes());
    }

    @Test
    void countsUpOncePerSignatureAndNeverForAnUnsignedRequest() {
        Signer signer = signer(XrdConst.kXR_secStandard);
        assertEquals(0, signer.sequence());
        assertEquals(1, signer.sign(frame(1, XrdConst.kXR_open, new byte[0])).sequence());
        assertNull(signer.sign(frame(2, XrdConst.kXR_read, new byte[0])));
        assertEquals(1, signer.sequence(), "an unsigned request does not consume a number");
        assertEquals(2, signer.sign(frame(3, XrdConst.kXR_rm, new byte[0])).sequence());
        assertEquals(2, signer.sequence());
    }

    @Test
    void leavesFileDataOutOfTheHashUnlessTheServerAskedForIt() {
        byte[] data = "file contents".getBytes(StandardCharsets.UTF_8);
        byte[] frame = frame(1, XrdConst.kXR_write, data);

        Signer.Signature without = signer(XrdConst.kXR_secStandard).sign(frame);
        assertTrue(without.nodata());
        byte[] header = java.util.Arrays.copyOf(frame, XrdConst.REQUEST_HDRLEN);
        assertArrayEquals(Aes.cbcEncrypt(KEY, Signer.hash(1, header, data, true)),
                without.bytes());

        Signer.Signature with = new Signer(KEY, XrdConst.kXR_secStandard, Map.of(), true, false)
                .sign(frame);
        assertFalse(with.nodata(), "kXR_secOData puts the data back in");
        assertArrayEquals(Aes.cbcEncrypt(KEY, Signer.hash(1, header, data, false)),
                with.bytes());
    }

    @Test
    void hashesOnlyWhatDlenDeclares() {
        // Two frames back to back: the second must not leak into the first's hash.
        byte[] first = frame(1, XrdConst.kXR_rm, "/store/f".getBytes(StandardCharsets.UTF_8));
        byte[] second = frame(2, XrdConst.kXR_rm, "/store/g".getBytes(StandardCharsets.UTF_8));
        byte[] both = new byte[first.length + second.length];
        System.arraycopy(first, 0, both, 0, first.length);
        System.arraycopy(second, 0, both, first.length, second.length);
        assertArrayEquals(signer(XrdConst.kXR_secStandard).sign(first).bytes(),
                signer(XrdConst.kXR_secStandard).sign(both).bytes());
    }

    @Test
    void prependsAFreshIvWhenTheHandshakeSignedItsDiffieHellman() {
        Signer signer = new Signer(KEY, XrdConst.kXR_secStandard, Map.of(), false, true);
        byte[] frame = frame(1, XrdConst.kXR_mkdir, new byte[0]);
        byte[] one = signer.sign(frame).bytes();
        byte[] two = signer.sign(frame).bytes();
        // A 32-byte hash is already a block multiple, so padding adds a whole
        // block of its own: 16 of IV then 48 of ciphertext.
        assertEquals(Aes.BLOCK_SIZE + 48, one.length);
        assertFalse(java.util.Arrays.equals(
                java.util.Arrays.copyOf(one, Aes.BLOCK_SIZE),
                java.util.Arrays.copyOf(two, Aes.BLOCK_SIZE)),
                "a fresh IV every time");

        byte[] iv = java.util.Arrays.copyOf(one, Aes.BLOCK_SIZE);
        byte[] body = java.util.Arrays.copyOfRange(one, Aes.BLOCK_SIZE, one.length);
        byte[] header = java.util.Arrays.copyOf(frame, XrdConst.REQUEST_HDRLEN);
        assertArrayEquals(Aes.cbcEncrypt(KEY, iv, Signer.hash(1, header, new byte[0], false), true),
                body);
    }

    @Test
    void keepsTheKeyOutOfItsOwnToString() {
        String text = signer(XrdConst.kXR_secStandard).toString();
        assertFalse(text.contains("0123456789abcdef"));
        assertTrue(text.contains("seqno=0"));
    }
}

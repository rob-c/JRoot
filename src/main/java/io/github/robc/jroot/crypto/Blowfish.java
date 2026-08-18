package io.github.robc.jroot.crypto;

import java.security.GeneralSecurityException;
import java.util.zip.CRC32;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import io.github.robc.jroot.XrdAuthException;

/**
 * Blowfish in CFB64, and the {@code bf32} transform built on it: what
 * {@code sss} mints its credential with, and what a session it authenticated
 * signs {@code kXR_sigver} frames with.
 *
 * <p>The JDK has the block cipher but not this mode — {@code Blowfish/CFB}
 * will not encrypt a trailing part-block, and every {@code bf32} blob ends in
 * one, since its length is whatever the plaintext was plus four. The feedback
 * loop is therefore run here over the JDK's ECB primitive, which is all CFB
 * needs: the block function is used in the encrypt direction whichever way
 * the data is going.
 *
 * <p>The IV is a caller's argument and is always eight zero bytes in this
 * protocol. That makes the output deterministic, which is the point — a
 * verifier checks a signature by encrypting the same plaintext and comparing,
 * never by decrypting.
 */
public final class Blowfish {

    public static final int BLOCK_SIZE = 8;

    /** Blowfish's own bounds: a key shorter or longer than this is not a key. */
    private static final int MIN_KEY = 4;
    private static final int MAX_KEY = 56;

    private final Cipher block;

    public Blowfish(byte[] key) {
        if (key.length < MIN_KEY || key.length > MAX_KEY) {
            throw new XrdAuthException("a Blowfish key is " + MIN_KEY + " to " + MAX_KEY
                    + " bytes, not " + key.length);
        }
        try {
            block = Cipher.getInstance("Blowfish/ECB/NoPadding");
            block.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "Blowfish"));
        } catch (GeneralSecurityException e) {
            throw new XrdAuthException("this JVM cannot do Blowfish: " + e.getMessage(), e);
        }
    }

    public byte[] encryptCfb64(byte[] iv, byte[] data) {
        return cfb64(iv, data, false);
    }

    public byte[] decryptCfb64(byte[] iv, byte[] data) {
        return cfb64(iv, data, true);
    }

    /**
     * {@code XrdCryptoLite}'s {@code bf32}: the IEEE CRC-32 of {@code plain}
     * appended big-endian, then the whole of it through CFB64 under a zero
     * IV. Four bytes longer than what went in, and the same bytes every time.
     */
    public static byte[] bf32(byte[] key, byte[] plain) {
        CRC32 crc = new CRC32();
        crc.update(plain);
        long value = crc.getValue();
        byte[] framed = new byte[plain.length + 4];
        System.arraycopy(plain, 0, framed, 0, plain.length);
        framed[plain.length] = (byte) (value >>> 24);
        framed[plain.length + 1] = (byte) (value >>> 16);
        framed[plain.length + 2] = (byte) (value >>> 8);
        framed[plain.length + 3] = (byte) value;
        return new Blowfish(key).encryptCfb64(new byte[BLOCK_SIZE], framed);
    }

    /**
     * CFB64 proper. The feedback register takes the ciphertext byte in both
     * directions, which is the only difference between them, and a final
     * part-block simply uses as much of the keystream as it needs.
     */
    private byte[] cfb64(byte[] iv, byte[] data, boolean decrypt) {
        if (iv.length != BLOCK_SIZE) {
            throw new XrdAuthException("a Blowfish IV is " + BLOCK_SIZE
                    + " bytes, not " + iv.length);
        }
        byte[] feedback = iv.clone();
        byte[] out = new byte[data.length];
        for (int base = 0; base < data.length; base += BLOCK_SIZE) {
            byte[] keystream = encryptBlock(feedback);
            int span = Math.min(BLOCK_SIZE, data.length - base);
            for (int i = 0; i < span; i++) {
                byte in = data[base + i];
                out[base + i] = (byte) (in ^ keystream[i]);
                feedback[i] = decrypt ? in : out[base + i];
            }
            if (span < BLOCK_SIZE) {
                System.arraycopy(keystream, span, feedback, span, BLOCK_SIZE - span);
            }
        }
        return out;
    }

    private byte[] encryptBlock(byte[] input) {
        try {
            return block.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new XrdAuthException("Blowfish failed: " + e.getMessage(), e);
        }
    }
}

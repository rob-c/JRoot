package io.github.robc.jroot.crypto;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import io.github.robc.jroot.XrdAuthException;

/**
 * The AES-CBC that GSI's session cipher and {@code kXR_sigver} both use.
 * A zero IV is the default because that is what an unsigned-DH session
 * signs under; it is not a general-purpose encryption helper.
 */
public final class Aes {

    private Aes() {}

    public static final int BLOCK_SIZE = 16;

    private static final byte[] ZERO_IV = new byte[BLOCK_SIZE];

    public static byte[] zeroIv() {
        return ZERO_IV.clone();
    }

    public static byte[] cbcEncrypt(byte[] key, byte[] data) {
        return cbc(Cipher.ENCRYPT_MODE, key, ZERO_IV, data, true);
    }

    public static byte[] cbcEncrypt(byte[] key, byte[] iv, byte[] data, boolean pad) {
        return cbc(Cipher.ENCRYPT_MODE, key, iv, data, pad);
    }

    public static byte[] cbcDecrypt(byte[] key, byte[] data) {
        return cbc(Cipher.DECRYPT_MODE, key, ZERO_IV, data, true);
    }

    public static byte[] cbcDecrypt(byte[] key, byte[] iv, byte[] data, boolean pad) {
        return cbc(Cipher.DECRYPT_MODE, key, iv, data, pad);
    }

    private static byte[] cbc(int mode, byte[] key, byte[] iv, byte[] data, boolean pad) {
        if (iv.length != BLOCK_SIZE) {
            throw new XrdAuthException("an AES IV is " + BLOCK_SIZE + " bytes, not " + iv.length);
        }
        try {
            Cipher cipher = Cipher.getInstance(
                    pad ? "AES/CBC/PKCS5Padding" : "AES/CBC/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new XrdAuthException("AES-CBC failed: " + e.getMessage(), e);
        }
    }
}

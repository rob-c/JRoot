package io.github.robc.jroot.crypto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;

import io.github.robc.jroot.XrdAuthException;
import io.github.robc.jroot.wire.XrdConst;

/**
 * {@code kXR_sigver} request signing — stock {@code XrdSecProtect}, secver 0.
 *
 * <p>When the server advertises a security level at or above
 * {@code kXR_secStandard}, covered opcodes must be preceded by a
 * {@code kXR_sigver} frame. What that frame carries is not an HMAC: the
 * reference scheme hashes and then encrypts. The signature is
 * {@code SHA-256(seqno_be64 || request_header || payload)} run through the
 * session cipher negotiated at login — AES-CBC under the GSI session key.
 * An unsigned-DH peer uses a zero IV and sends the ciphertext alone; a
 * signed-DH peer draws a fresh IV per signature and prepends it. A
 * data-bearing request ({@code kXR_write}, {@code kXR_pgwrite}) is hashed
 * <em>without</em> its payload unless the server negotiated
 * {@code kXR_secOData}, and the frame says so with {@code kXR_nodata_sig}.
 *
 * <p>Which cipher runs is the authenticated mechanism's business, not the
 * protocol's: GSI signs under the AES key it agreed, and {@code sss} under
 * {@code bf32} with the shared secret, the same transform that minted its
 * credential.
 */
public final class Signer {

    /** Opcodes that mutate state, and so are signed from standard up. */
    public static final Set<Integer> SIGNED_OPCODES = Set.of(
            XrdConst.kXR_chmod, XrdConst.kXR_fattr, XrdConst.kXR_mkdir, XrdConst.kXR_mv,
            XrdConst.kXR_open, XrdConst.kXR_pgwrite, XrdConst.kXR_prepare, XrdConst.kXR_rm,
            XrdConst.kXR_rmdir, XrdConst.kXR_set, XrdConst.kXR_truncate, XrdConst.kXR_write,
            XrdConst.kXR_writev, XrdConst.kXR_chkpoint, XrdConst.kXR_clone);

    /** What {@code kXR_secIntense} adds: the requests that name a file or path. */
    private static final Set<Integer> INTENSE_OPCODES = Set.of(
            XrdConst.kXR_close, XrdConst.kXR_dirlist, XrdConst.kXR_locate, XrdConst.kXR_stat);

    /** The requests whose payload is file data rather than arguments. */
    private static final Set<Integer> DATA_OPCODES =
            Set.of(XrdConst.kXR_write, XrdConst.kXR_pgwrite);

    /** One signature, ready to be wrapped in a {@code kXR_sigver} request. */
    public record Signature(long sequence, byte[] bytes, boolean nodata) {}

    /** The session ciphers a signature can be encrypted under. */
    public enum Cipher { AES_CBC, BF32 }

    private final byte[] key;
    private final Cipher cipher;
    private final int level;
    private final Map<Integer, Integer> overrides;
    private final boolean signData;
    private final boolean embeddedIv;
    private final SecureRandom random;
    private long sequence;

    public Signer(byte[] key, int level, Map<Integer, Integer> overrides,
                  boolean signData, boolean embeddedIv) {
        this(key, Cipher.AES_CBC, level, overrides, signData, embeddedIv);
    }

    public Signer(byte[] key, Cipher cipher, int level, Map<Integer, Integer> overrides,
                  boolean signData, boolean embeddedIv) {
        this.key = key.clone();
        this.cipher = cipher;
        this.level = level;
        this.overrides = Map.copyOf(overrides);
        this.signData = signData;
        this.embeddedIv = embeddedIv;
        this.random = embeddedIv && cipher == Cipher.AES_CBC ? new SecureRandom() : null;
    }

    /**
     * Whether {@code opcode} needs a signature at {@code level}. The
     * per-opcode table from the {@code kXR_protocol} security block wins:
     * {@code kXR_secNone} there exempts an otherwise-covered opcode, and any
     * other value pulls one in.
     */
    public static boolean isSigned(int opcode, int level, Map<Integer, Integer> overrides) {
        Integer override = overrides.get(opcode);
        if (override != null) {
            return override != XrdConst.kXR_secNone;
        }
        return switch (level) {
            case XrdConst.kXR_secNone, XrdConst.kXR_secCompatible -> false;
            case XrdConst.kXR_secStandard -> SIGNED_OPCODES.contains(opcode);
            case XrdConst.kXR_secIntense ->
                    SIGNED_OPCODES.contains(opcode) || INTENSE_OPCODES.contains(opcode);
            case XrdConst.kXR_secPedantic ->
                    opcode >= XrdConst.kXR_1stRequest && opcode <= XrdConst.kXR_clone;
            default -> SIGNED_OPCODES.contains(opcode);
        };
    }

    public boolean required(int opcode) {
        return key.length > 0 && isSigned(opcode, level, overrides);
    }

    public long sequence() {
        return sequence;
    }

    /** What is signed: SHA-256 over the sequence number, header and payload. */
    public static byte[] hash(long sequence, byte[] header, byte[] payload, boolean nodata) {
        MessageDigest sha256;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new XrdAuthException("this JVM has no SHA-256", e);
        }
        sha256.update(ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN)
                .putLong(sequence).array());
        sha256.update(header);
        if (!nodata) {
            sha256.update(payload);
        }
        return sha256.digest();
    }

    /**
     * Sign an encoded request frame, or return {@code null} when the opcode
     * needs no signature. The sequence number is monotonic per connection
     * and must never repeat, so this is the only thing that advances it.
     */
    public synchronized Signature sign(byte[] frame) {
        int opcode = ((frame[2] & 0xFF) << 8) | (frame[3] & 0xFF);
        if (!required(opcode)) {
            return null;
        }
        sequence++;
        byte[] header = new byte[XrdConst.REQUEST_HDRLEN];
        System.arraycopy(frame, 0, header, 0, header.length);
        // Exactly what dlen declares, not everything after the header: the
        // frame is the request, and anything appended after it is the next one.
        int dlen = ByteBuffer.wrap(frame, XrdConst.REQUEST_HDRLEN - 4, 4).getInt();
        byte[] payload = new byte[Math.max(dlen, 0)];
        System.arraycopy(frame, XrdConst.REQUEST_HDRLEN, payload, 0, payload.length);

        boolean nodata = DATA_OPCODES.contains(opcode) && !signData;
        byte[] digest = hash(sequence, header, payload, nodata);
        return new Signature(sequence, encrypt(digest), nodata);
    }

    /**
     * The digest under the session cipher. {@code bf32} has no IV to choose
     * and no padding to add — its output is the digest plus the four bytes of
     * its CRC — so the signed-DH embedded IV simply does not arise there.
     */
    private byte[] encrypt(byte[] digest) {
        if (cipher == Cipher.BF32) {
            return Blowfish.bf32(key, digest);
        }
        byte[] signature;
        if (embeddedIv) {
            byte[] iv = new byte[Aes.BLOCK_SIZE];
            random.nextBytes(iv);
            byte[] encrypted = Aes.cbcEncrypt(key, iv, digest, true);
            signature = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, signature, 0, iv.length);
            System.arraycopy(encrypted, 0, signature, iv.length, encrypted.length);
        } else {
            signature = Aes.cbcEncrypt(key, digest);
        }
        return signature;
    }

    @Override
    public String toString() {
        return "Signer[" + cipher + ", level=" + level + ", seqno=" + sequence
                + ", key=<redacted>]";
    }
}

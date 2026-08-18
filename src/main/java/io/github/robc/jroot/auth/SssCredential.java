package io.github.robc.jroot.auth;

import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdAuthException;
import io.github.robc.jroot.crypto.Blowfish;
import io.github.robc.jroot.crypto.Signer;

/**
 * {@code sss} — Simple Shared Secret. Client and server hold the same key in
 * a keytab, and the credential proves possession of it by encrypting a
 * freshly minted, timestamped blob that only the holder could have produced.
 *
 * <p>The blob is a sixteen-byte cleartext header — {@code "sss\0"}, a version,
 * a spare byte, the length of the key name, the cipher marker {@code '0'} for
 * Blowfish-CFB64, and the key's id big-endian — followed by {@code bf32} over
 * a forty-byte data header (a 32-byte nonce, the generation time relative to
 * an epoch of its own, and an options byte) and a NAME type-length-value
 * carrying the user this client claims to be.
 *
 * <p>There is one round trip and no challenge: the server decrypts, checks
 * the CRC and the age, and either accepts or does not. The shared secret then
 * stays as the session key, because it is also what {@code kXR_sigver} frames
 * are signed with when the server demands signing.
 */
public final class SssCredential implements Credential {

    /** The cleartext header, before the encrypted body. */
    static final int HEADER_LEN = 16;

    /** Nonce, generation time and options, all inside the encryption. */
    static final int DATA_HEADER_LEN = 40;

    static final int NONCE_LEN = 32;

    /** SSS counts seconds from 2008-09-23T14:11:20Z, not from the Unix epoch. */
    static final long BASE_TIME = 1222183880L;

    /** {@code kXRS_bf32}: the body is Blowfish-CFB64 with a CRC-32. */
    static final byte ENCRYPTION_BF32 = '0';

    /** {@code XrdSecsssRR_Data::Opts}: the credential stands on its own. */
    static final byte OPT_USEDATA = 0x00;

    /** The type-length-value that carries a name. */
    static final byte TYPE_NAME = 0x01;

    /** What the {@code NAME} value may occupy, its terminator included. */
    static final int MAX_NAME = 64;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final SssKeytab.Key key;
    private final String username;

    public SssCredential(SssKeytab.Key key, String username) {
        this.key = key;
        this.username = username == null || username.isBlank() ? "xrd" : username;
    }

    @Override
    public String name() {
        return "sss";
    }

    @Override
    public byte[] initial() {
        if (key.isExpired()) {
            throw new XrdAuthException("the SSS key " + key.id() + " expired at "
                    + Instant.ofEpochSecond(key.expires()));
        }
        byte[] nonce = new byte[NONCE_LEN];
        RANDOM.nextBytes(nonce);
        return encode(key, username, nonce, Instant.now().getEpochSecond() - BASE_TIME);
    }

    /** The shared secret doubles as the session key: {@code kXR_sigver} under
     *  {@code sss} is {@code bf32} with this same key. */
    @Override
    public byte[] sessionKey() {
        return key.secret().clone();
    }

    @Override
    public Signer.Cipher sessionCipher() {
        return Signer.Cipher.BF32;
    }

    public SssKeytab.Key key() {
        return key;
    }

    /**
     * Mint a credential. The nonce and generation time are arguments so that
     * a test can pin the encoding; nothing else should be choosing them.
     */
    static byte[] encode(SssKeytab.Key key, String username, byte[] nonce, long generated) {
        if (nonce.length != NONCE_LEN) {
            throw new XrdAuthException("an SSS nonce is " + NONCE_LEN + " bytes, not "
                    + nonce.length);
        }
        byte[] user = username.getBytes(StandardCharsets.UTF_8);
        int length = Math.min(user.length + 1, MAX_NAME);       // the NUL counts

        byte[] body = new byte[DATA_HEADER_LEN + 3 + length];
        System.arraycopy(nonce, 0, body, 0, NONCE_LEN);
        ByteBuffer.wrap(body, NONCE_LEN, 4).order(ByteOrder.BIG_ENDIAN)
                .putInt((int) generated);
        body[DATA_HEADER_LEN - 1] = OPT_USEDATA;
        body[DATA_HEADER_LEN] = TYPE_NAME;
        body[DATA_HEADER_LEN + 2] = (byte) length;
        System.arraycopy(user, 0, body, DATA_HEADER_LEN + 3, length - 1);

        byte[] encrypted = Blowfish.bf32(key.secret(), body);
        byte[] out = new byte[HEADER_LEN + encrypted.length];
        out[0] = 's';
        out[1] = 's';
        out[2] = 's';
        out[4] = 1;                                             // protocol version
        // The key-name length stays zero: the id in the header is what
        // selects the key, and a named header is only how the C client asks a
        // server to look one up by name instead.
        out[7] = ENCRYPTION_BF32;
        ByteBuffer.wrap(out, 8, 8).order(ByteOrder.BIG_ENDIAN).putLong(key.id());
        System.arraycopy(encrypted, 0, out, HEADER_LEN, encrypted.length);
        return out;
    }

    /**
     * Build an {@code sss} credential for a server's offer, or empty when
     * there is no keytab to build one from. A server that names a key
     * ({@code n:<name>}) gets that key or nothing — falling back to another
     * key would authenticate as somebody else.
     */
    public static Optional<SssCredential> available(SecurityOffer offer, Config config) {
        Path path = config.keytab() != null ? config.keytab() : SssKeytab.defaultPath();
        if (!Files.isRegularFile(path)) {
            return Optional.empty();
        }
        List<SssKeytab.Key> keys;
        try {
            keys = SssKeytab.read(path);
        } catch (UncheckedIOException e) {
            return Optional.empty();
        }
        String wanted = offer.options().get("n");
        for (SssKeytab.Key key : keys) {
            if (wanted == null || wanted.equals(key.name())) {
                return Optional.of(new SssCredential(key, config.username()));
            }
        }
        if (wanted != null && !keys.isEmpty()) {
            throw new XrdAuthException(path + " holds no key named " + wanted
                    + ", which is the one this server asks for");
        }
        return Optional.empty();
    }

    @Override
    public String toString() {
        return "SssCredential[" + key + ", user=" + username + "]";
    }
}

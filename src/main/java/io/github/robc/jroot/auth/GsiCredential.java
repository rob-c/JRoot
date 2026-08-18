package io.github.robc.jroot.auth;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import io.github.robc.jroot.XrdAuthException;
import io.github.robc.jroot.auth.GsiMessage.Bucket;
import io.github.robc.jroot.crypto.Aes;
import io.github.robc.jroot.crypto.Der;
import io.github.robc.jroot.crypto.Pem;
import io.github.robc.jroot.crypto.RsaKeys;
import io.github.robc.jroot.crypto.X509Proxy;

/**
 * {@code gsi} — X.509 proxy authentication.
 *
 * <p>This implements the two-round unsigned-Diffie-Hellman path, which is
 * what a stock client negotiates when it advertises a version below
 * {@code XrdSecgsiVersDHsigned}:
 *
 * <ol>
 *   <li>{@code kXGC_certreq} — the client names its crypto module, its
 *       version, the CA hash the server asked for and a random tag, with a
 *       nested message holding the tag the <em>server</em> must sign.</li>
 *   <li>{@code kXGS_cert} — the server answers with its Diffie-Hellman
 *       public blob and a random tag of its own.</li>
 *   <li>{@code kXGC_cert} — the client agrees an AES-128 session key over
 *       that group, signs the server's tag with the proxy's private key
 *       (proof of possession), and returns its own public value plus the
 *       proxy chain, encrypted under the session key.</li>
 * </ol>
 *
 * <p>Not implemented, and refused by name rather than mis-answered: the
 * signed-DH path (the server offers {@code kXRS_cipher} instead of
 * {@code kXRS_puk}) and X.509 delegation ({@code kXGS_pxyreq}).
 */
public final class GsiCredential implements Credential {

    /** Advertised so the server chooses unsigned DH. Anything at or above
     *  {@code XrdSecgsiVersDHsigned} (10400) selects signed DH. */
    public static final int VERSION_UNSIGNED_DH = 10300;
    /** A stock client's options, with proxy delegation off. */
    public static final int CLIENT_OPTS_NO_DELEGATION = 0x80;
    /** AES-128: the session key is the leading 16 bytes of the shared secret. */
    public static final int SESSION_KEY_LEN = 16;
    public static final int RTAG_LEN = 8;

    private static final byte[] BPUB = "---BPUB---".getBytes(StandardCharsets.US_ASCII);
    /** The reference encoder drops the final dash when it writes the closing
     *  delimiter, so matching on nine bytes is what actually parses. */
    private static final byte[] EPUB = "---EPUB--".getBytes(StandardCharsets.US_ASCII);

    private final X509Proxy proxy;
    private final String cryptoModule;
    private final String issuerHash;
    private final SecureRandom random = new SecureRandom();
    private byte[] rtag = new byte[0];
    private byte[] sessionKey;

    public GsiCredential(X509Proxy proxy, String cryptoModule, String issuerHash) {
        this.proxy = proxy;
        this.cryptoModule = cryptoModule == null || cryptoModule.isBlank() ? "ssl" : cryptoModule;
        this.issuerHash = issuerHash == null ? "" : issuerHash;
    }

    /** Build a GSI credential from the proxy the environment points at, or
     *  empty when there is no usable one. */
    public static Optional<GsiCredential> available(SecurityOffer offer, Path proxyPath) {
        Path path = proxyPath != null ? proxyPath : X509Proxy.defaultPath();
        if (!Files.isReadable(path)) {
            return Optional.empty();
        }
        X509Proxy proxy;
        try {
            proxy = X509Proxy.load(path);
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
        if (proxy.isExpired()) {
            throw new XrdAuthException("the X.509 proxy " + path + " expired at "
                    + proxy.expiry() + "; renew it");
        }
        var options = offer.options();
        return Optional.of(new GsiCredential(proxy,
                options.getOrDefault("c", "ssl"), options.getOrDefault("ca", "")));
    }

    public X509Proxy proxy() {
        return proxy;
    }

    @Override
    public String name() {
        return "gsi";
    }

    @Override
    public byte[] sessionKey() {
        return sessionKey;
    }

    @Override
    public byte[] initial() {
        if (proxy.isExpired()) {
            throw new XrdAuthException("the X.509 proxy " + proxy.path() + " expired at "
                    + proxy.expiry() + "; renew it");
        }
        rtag = new byte[RTAG_LEN];
        random.nextBytes(rtag);
        return certreq(cryptoModule, VERSION_UNSIGNED_DH, issuerHash,
                CLIENT_OPTS_NO_DELEGATION, rtag);
    }

    @Override
    public byte[] step(byte[] challenge) {
        int step = GsiMessage.decode(challenge).step();
        if (step == GsiMessage.STEP_SERVER_CERT) {
            return certResponse(challenge);
        }
        if (step == GsiMessage.STEP_SERVER_PXYREQ) {
            throw new XrdAuthException(
                    "the server asked for X.509 delegation, which this client does not do");
        }
        throw new XrdAuthException("unexpected GSI step " + step + " from the server");
    }

    /** The first client message, {@code kXGC_certreq}. No cryptography involved. */
    static byte[] certreq(String cryptoModule, int version, String issuerHash,
                          int options, byte[] rtag) {
        byte[] inner = GsiMessage.encode(GsiMessage.STEP_CLIENT_CERTREQ,
                List.of(new Bucket(GsiMessage.BUCKET_RTAG, rtag)));
        return GsiMessage.encode(GsiMessage.STEP_CLIENT_CERTREQ, List.of(
                Bucket.of(GsiMessage.BUCKET_CRYPTOMOD, cryptoModule),
                Bucket.of(GsiMessage.BUCKET_VERSION, version),
                Bucket.of(GsiMessage.BUCKET_ISSUER_HASH, issuerHash),
                Bucket.of(GsiMessage.BUCKET_CLNT_OPTS, options),
                new Bucket(GsiMessage.BUCKET_MAIN, inner)));
    }

    /** Answer {@code kXGS_cert} with {@code kXGC_cert}. */
    private byte[] certResponse(byte[] challenge) {
        GsiMessage.Decoded message = GsiMessage.decode(challenge);
        byte[] blob = message.find(GsiMessage.BUCKET_PUK);
        if (blob == null) {
            if (message.find(GsiMessage.BUCKET_CIPHER) != null) {
                throw new XrdAuthException(
                        "the server chose GSI signed-DH; this client implements unsigned-DH only");
            }
            throw new XrdAuthException("the server's GSI challenge carries no DH public key");
        }
        PeerPublic peer = parsePeerBlob(blob);
        BigInteger priv = privateExponent(peer.p());
        sessionKey = sessionKey(peer, priv);

        List<Bucket> inner = new ArrayList<>();
        inner.add(new Bucket(GsiMessage.BUCKET_X509, proxy.pem()));
        byte[] main = message.find(GsiMessage.BUCKET_MAIN);
        byte[] serverTag = main != null ? GsiMessage.find(main, GsiMessage.BUCKET_RTAG) : null;
        if (serverTag != null && serverTag.length > 0) {
            // Proof of possession: raw PKCS#1 v1.5 over the server's tag.
            inner.add(new Bucket(GsiMessage.BUCKET_SIGNED_RTAG,
                    RsaKeys.signRaw(proxy.key(), serverTag)));
        }
        byte[] ownTag = new byte[RTAG_LEN];
        random.nextBytes(ownTag);
        inner.add(new Bucket(GsiMessage.BUCKET_RTAG, ownTag));

        byte[] encrypted = Aes.cbcEncrypt(sessionKey,
                GsiMessage.encode(GsiMessage.STEP_CLIENT_CERT, inner));
        return GsiMessage.encode(GsiMessage.STEP_CLIENT_CERT, List.of(
                Bucket.of(GsiMessage.BUCKET_CRYPTOMOD, "ssl"),
                new Bucket(GsiMessage.BUCKET_PUK,
                        publicBlob(peer.paramsPem(), peer.g().modPow(priv, peer.p()))),
                Bucket.of(GsiMessage.BUCKET_CIPHER_ALG, "aes-128-cbc"),
                Bucket.of(GsiMessage.BUCKET_MD_ALG, "sha256"),
                new Bucket(GsiMessage.BUCKET_MAIN, encrypted)));
    }

    // -----------------------------------------------------------------
    // Diffie-Hellman over the server's group
    // -----------------------------------------------------------------

    /** The server's DH blob: the PEM parameters, the group, its public value. */
    record PeerPublic(byte[] paramsPem, BigInteger p, BigInteger g, BigInteger publicValue) {}

    /** The prime and generator of a {@code DH PARAMETERS} PEM block. */
    static BigInteger[] parseDhParameters(byte[] pem) {
        for (Pem.Block block : Pem.blocks(pem)) {
            if (!block.label().endsWith("PARAMETERS")) {
                continue;
            }
            List<Der.Element> fields = Der.sequence(block.der());
            if (fields.size() < 2) {
                throw new XrdAuthException("DH parameters carry no prime and base");
            }
            return new BigInteger[] {fields.get(0).integer(), fields.get(1).integer()};
        }
        throw new XrdAuthException("no PEM block in the server's DH parameters");
    }

    /** Split {@code <PEM params>---BPUB---<hex>---EPUB---} into its parts. */
    static PeerPublic parsePeerBlob(byte[] blob) {
        int start = indexOf(blob, BPUB, 0);
        int end = start < 0 ? -1 : indexOf(blob, EPUB, start + BPUB.length);
        if (start < 0 || end <= start + BPUB.length) {
            throw new XrdAuthException("malformed GSI DH public blob");
        }
        byte[] params = new byte[start];
        System.arraycopy(blob, 0, params, 0, start);
        String hex = new String(blob, start + BPUB.length,
                end - start - BPUB.length, StandardCharsets.US_ASCII).strip();
        BigInteger publicValue;
        try {
            publicValue = new BigInteger(hex, 16);
        } catch (NumberFormatException e) {
            throw new XrdAuthException("the DH public value is not hexadecimal", e);
        }
        BigInteger[] group = parseDhParameters(params);
        return new PeerPublic(params, group[0], group[1], publicValue);
    }

    /** The client's blob: the server's parameters echoed, then our public value. */
    static byte[] publicBlob(byte[] paramsPem, BigInteger publicValue) {
        byte[] magnitude = unsigned(publicValue);
        StringBuilder hex = new StringBuilder(magnitude.length * 2);
        for (byte b : magnitude) {
            hex.append(String.format("%02X", b));
        }
        byte[] tail = ("---BPUB---" + hex + "---EPUB---").getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[paramsPem.length + tail.length];
        System.arraycopy(paramsPem, 0, out, 0, paramsPem.length);
        System.arraycopy(tail, 0, out, paramsPem.length, tail.length);
        return out;
    }

    /**
     * The leading bytes of the DH shared secret. XrdSecgsi's unsigned path
     * takes the secret's <em>minimal</em> big-endian form — leading zeros
     * stripped, as OpenSSL's {@code DH_compute_key} returns it — and uses
     * its first bytes directly, with no KDF.
     */
    static byte[] sessionKey(PeerPublic peer, BigInteger privateExponent) {
        byte[] raw = unsigned(peer.publicValue().modPow(privateExponent, peer.p()));
        if (raw.length < SESSION_KEY_LEN) {
            throw new XrdAuthException("the DH shared secret is " + raw.length
                    + " bytes, need " + SESSION_KEY_LEN);
        }
        byte[] key = new byte[SESSION_KEY_LEN];
        System.arraycopy(raw, 0, key, 0, SESSION_KEY_LEN);
        return key;
    }

    /** A private exponent in [2, p-2]; the group is the server's choice. */
    private BigInteger privateExponent(BigInteger p) {
        byte[] bytes = new byte[(p.bitLength() + 7) / 8];
        random.nextBytes(bytes);
        return new BigInteger(1, bytes).mod(p.subtract(BigInteger.valueOf(3)))
                .add(BigInteger.TWO);
    }

    /** Big-endian magnitude, without the sign byte {@link BigInteger} may add. */
    private static byte[] unsigned(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length > 1 && raw[0] == 0) {
            byte[] out = new byte[raw.length - 1];
            System.arraycopy(raw, 1, out, 0, out.length);
            return out;
        }
        return raw;
    }

    private static int indexOf(byte[] haystack, byte[] needle, int from) {
        outer:
        for (int i = Math.max(from, 0); i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    @Override
    public String toString() {
        return "GsiCredential[" + proxy.identity() + "]";
    }
}

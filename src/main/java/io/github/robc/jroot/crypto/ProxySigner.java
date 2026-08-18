package io.github.robc.jroot.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import io.github.robc.jroot.XrdAuthException;
import io.github.robc.jroot.crypto.Der.Element;

/**
 * Signing a certificate request into an RFC 3820 proxy — the client half of
 * X.509 delegation.
 *
 * <p>A server that needs to act for a user asks for a proxy rather than for
 * the user's key: it makes a key pair of its own, sends the public half as a
 * PKCS#10 request, and the client signs that into a certificate one level
 * below its own. The server then holds a credential that carries the user's
 * identity, expires when the user's proxy does, and never touched the user's
 * private key.
 *
 * <p>What is issued is deliberately the least the protocol allows: the
 * lifetime is the parent's — a delegated proxy that outlived what delegated
 * it would be a way to launder an expiry — the policy is
 * {@code id-ppl-inheritAll}, and there is no path length, which is what
 * every grid service expects to receive.
 */
public final class ProxySigner {

    private ProxySigner() {}

    private static final String SHA256_WITH_RSA = "1.2.840.113549.1.1.11";
    private static final String KEY_USAGE = "2.5.29.15";
    private static final String PROXY_CERT_INFO = "1.3.6.1.5.5.7.1.14";
    private static final String INHERIT_ALL = "1.3.6.1.5.5.7.21.1";
    private static final String COMMON_NAME = "2.5.4.3";

    /** Backdated a little, because two hosts rarely agree on the second. */
    private static final Duration BACKDATE = Duration.ofMinutes(5);

    /** Signature algorithm OIDs a request may be signed with, and the JCA
     *  names that verify them. */
    private static final Map<String, String> SIGNATURE_NAMES = Map.of(
            "1.2.840.113549.1.1.5", "SHA1withRSA",
            "1.2.840.113549.1.1.11", "SHA256withRSA",
            "1.2.840.113549.1.1.12", "SHA384withRSA",
            "1.2.840.113549.1.1.13", "SHA512withRSA",
            "1.2.840.10045.4.3.2", "SHA256withECDSA",
            "1.2.840.10045.4.3.3", "SHA384withECDSA",
            "1.2.840.10045.4.3.4", "SHA512withECDSA");

    /** The signed proxy and the chain it hangs from, leaf first. */
    public record Delegated(X509Certificate certificate, List<X509Certificate> chain) {

        /** The chain as concatenated PEM, which is what GSI sends back. */
        public byte[] pem() {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (X509Certificate cert : chain) {
                try {
                    out.writeBytes(Pem.encode("CERTIFICATE", cert.getEncoded()));
                } catch (CertificateEncodingException e) {
                    throw new XrdAuthException("a delegated certificate will not re-encode", e);
                }
            }
            return out.toByteArray();
        }
    }

    /**
     * Sign {@code request} — a PKCS#10 in PEM or bare DER — into a proxy one
     * level below {@code parent}.
     *
     * @throws XrdAuthException if the request is malformed, is signed by a key
     *                          other than the one it carries, or the parent
     *                          has already expired
     */
    public static Delegated sign(X509Proxy parent, byte[] request) {
        if (parent.isExpired()) {
            throw new XrdAuthException("the X.509 proxy " + parent.path()
                    + " expired at " + parent.expiry() + "; it cannot delegate");
        }
        byte[] der = derOf(request);
        byte[] publicKeyInfo = verifiedPublicKey(der);

        BigInteger serial = serialNumber();
        byte[] issuer = parent.certificate().getSubjectX500Principal().getEncoded();
        byte[] subject = appendCommonName(issuer, serial.toString());
        byte[] algorithm = DerWriter.sequenceOf(
                DerWriter.oid(SHA256_WITH_RSA), DerWriter.nullValue());

        Instant from = Instant.now().minus(BACKDATE);
        Instant until = parent.expiry();
        byte[] tbs = DerWriter.sequenceOf(
                DerWriter.explicit(0, DerWriter.integer(2)),        // v3
                DerWriter.integer(serial),
                algorithm,
                issuer,
                DerWriter.sequenceOf(DerWriter.time(from), DerWriter.time(until)),
                subject,
                publicKeyInfo,
                DerWriter.explicit(3, DerWriter.sequenceOf(keyUsage(), proxyCertInfo())));

        byte[] certificate = DerWriter.sequenceOf(tbs, algorithm,
                DerWriter.bitString(signature(parent, tbs), 0));

        List<X509Certificate> chain = new ArrayList<>();
        chain.add(decode(certificate));
        chain.addAll(parent.chain());
        return new Delegated(chain.get(0), List.copyOf(chain));
    }

    /** PEM if it looks like PEM, otherwise the bytes as they came. */
    private static byte[] derOf(byte[] request) {
        List<byte[]> blocks = Pem.blocks(request, "CERTIFICATE REQUEST");
        if (!blocks.isEmpty()) {
            return blocks.get(0);
        }
        blocks = Pem.blocks(request, "NEW CERTIFICATE REQUEST");
        return blocks.isEmpty() ? request : blocks.get(0);
    }

    /**
     * The {@code SubjectPublicKeyInfo} of a PKCS#10, after checking that the
     * request is signed by the key it carries. Proof of possession is the
     * only thing the client can check about a request, and skipping it would
     * let anything that could reach the socket have a proxy made for a key it
     * does not hold.
     */
    private static byte[] verifiedPublicKey(byte[] der) {
        List<Element> request = sequenceOrFail(der, "certificate request");
        if (request.size() < 3) {
            throw new XrdAuthException("a certificate request needs an info block,"
                    + " an algorithm and a signature; found " + request.size() + " fields");
        }
        Element info = request.get(0);
        List<Element> fields = info.children();
        if (fields.size() < 3) {
            throw new XrdAuthException("the certificate request's info block is too short");
        }
        byte[] publicKeyInfo = DerWriter.tagged(fields.get(2).tag(), fields.get(2).value());

        String algorithm = request.get(1).children().get(0).oid();
        String jca = SIGNATURE_NAMES.get(algorithm);
        if (jca == null) {
            throw new XrdAuthException("the certificate request is signed with "
                    + algorithm + ", which this client cannot check");
        }
        byte[] signed = request.get(2).value();
        if (signed.length == 0) {
            throw new XrdAuthException("the certificate request carries an empty signature");
        }
        // A BIT STRING's first content octet counts the unused trailing bits;
        // a signature always ends on a byte, so it is the rest that is signed.
        byte[] bytes = new byte[signed.length - 1];
        System.arraycopy(signed, 1, bytes, 0, bytes.length);
        try {
            PublicKey key = KeyFactory.getInstance(algorithm.startsWith("1.2.840.10045")
                            ? "EC" : "RSA")
                    .generatePublic(new X509EncodedKeySpec(publicKeyInfo));
            Signature verifier = Signature.getInstance(jca);
            verifier.initVerify(key);
            verifier.update(DerWriter.tagged(info.tag(), info.value()));
            if (!verifier.verify(bytes)) {
                throw new XrdAuthException("the certificate request is not signed by the key"
                        + " it asks to have certified");
            }
        } catch (GeneralSecurityException e) {
            throw new XrdAuthException("unusable certificate request: " + e.getMessage(), e);
        }
        return publicKeyInfo;
    }

    private static List<Element> sequenceOrFail(byte[] der, String what) {
        try {
            return Der.sequence(der);
        } catch (Der.DerException e) {
            throw new XrdAuthException("unreadable " + what + ": " + e.getMessage(), e);
        }
    }

    /** RFC 3820: the proxy's own CN is its serial number, so the subject of a
     *  proxy names the certificate that issued it and then itself. */
    private static byte[] appendCommonName(byte[] name, String value) {
        List<Element> rdns = sequenceOrFail(name, "distinguished name");
        byte[][] parts = new byte[rdns.size() + 1][];
        for (int i = 0; i < rdns.size(); i++) {
            parts[i] = DerWriter.tagged(rdns.get(i).tag(), rdns.get(i).value());
        }
        parts[rdns.size()] = DerWriter.setOf(DerWriter.sequenceOf(
                DerWriter.oid(COMMON_NAME), DerWriter.printableString(value)));
        return DerWriter.sequenceOf(parts);
    }

    /** A serial that is also a legal CN: positive, and small enough to read. */
    private static BigInteger serialNumber() {
        byte[] raw = new byte[8];
        new SecureRandom().nextBytes(raw);
        return new BigInteger(1, raw).mod(BigInteger.valueOf(Integer.MAX_VALUE))
                .add(BigInteger.ONE);
    }

    /** {@code digitalSignature} and {@code keyEncipherment}, critical, which
     *  is what a proxy is allowed to do and no more. */
    private static byte[] keyUsage() {
        return DerWriter.sequenceOf(
                DerWriter.oid(KEY_USAGE),
                DerWriter.bool(true),
                DerWriter.octetString(DerWriter.bitString(new byte[] {(byte) 0xA0}, 5)));
    }

    /** {@code ProxyCertInfo} with no path length and the inherit-all policy:
     *  the extension that makes this a proxy rather than a certificate the
     *  parent had no right to issue. */
    private static byte[] proxyCertInfo() {
        byte[] value = DerWriter.sequenceOf(
                DerWriter.sequenceOf(DerWriter.oid(INHERIT_ALL)));
        return DerWriter.sequenceOf(
                DerWriter.oid(PROXY_CERT_INFO),
                DerWriter.bool(true),
                DerWriter.octetString(value));
    }

    private static byte[] signature(X509Proxy parent, byte[] tbs) {
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(parent.key());
            signer.update(tbs);
            return signer.sign();
        } catch (GeneralSecurityException e) {
            throw new XrdAuthException("cannot sign a delegated proxy with "
                    + parent.path() + ": " + e.getMessage(), e);
        }
    }

    /** Back through the JDK's own parser, so that anything this builder got
     *  wrong fails here rather than at the far end. */
    private static X509Certificate decode(byte[] der) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (GeneralSecurityException e) {
            throw new XrdAuthException("the delegated proxy this client built will not"
                    + " parse: " + e.getMessage(), e);
        }
    }
}

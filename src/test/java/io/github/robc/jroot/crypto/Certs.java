package io.github.robc.jroot.crypto;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;

/**
 * Certificates for the tests that need real ones: a CA, what it issues, and
 * the PKCS#10 a server sends when it asks for a delegated proxy.
 *
 * <p>The JDK can read certificates and cannot write them, so these are built
 * with {@link DerWriter} — the same encoder {@link ProxySigner} uses. That is
 * on purpose: a test fixture the JDK's own parser accepts is evidence the
 * encoder is right, and a bug in it fails these tests loudly rather than
 * hiding behind a second implementation.
 */
public final class Certs {

    private Certs() {}

    private static final String SHA256_WITH_RSA = "1.2.840.113549.1.1.11";
    private static final String COMMON_NAME = "2.5.4.3";
    private static final String BASIC_CONSTRAINTS = "2.5.29.19";

    public static KeyPair keyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new AssertionError("this JVM cannot make an RSA key", e);
        }
    }

    /** A self-signed certificate authority, valid from an hour ago. */
    public static X509Certificate ca(KeyPair keys, String cn, Duration life) {
        return issue(name(cn), keys.getPublic().getEncoded(), name(cn), keys.getPrivate(),
                Instant.now().minus(Duration.ofHours(1)), Instant.now().plus(life), true);
    }

    /** An end-entity certificate signed by {@code issuer}. */
    public static X509Certificate issued(X509Certificate issuer, PrivateKey issuerKey,
                                         KeyPair subject, String cn, Duration life) {
        return issue(issuer.getSubjectX500Principal().getEncoded(),
                subject.getPublic().getEncoded(), name(cn), issuerKey,
                Instant.now().minus(Duration.ofHours(1)), Instant.now().plus(life), false);
    }

    /** A certificate whose validity has already run out. */
    public static X509Certificate expired(X509Certificate issuer, PrivateKey issuerKey,
                                          KeyPair subject, String cn) {
        return issue(issuer.getSubjectX500Principal().getEncoded(),
                subject.getPublic().getEncoded(), name(cn), issuerKey,
                Instant.now().minus(Duration.ofDays(2)),
                Instant.now().minus(Duration.ofDays(1)), false);
    }

    private static X509Certificate issue(byte[] issuer, byte[] publicKeyInfo, byte[] subject,
                                         PrivateKey key, Instant from, Instant until,
                                         boolean authority) {
        byte[] algorithm = DerWriter.sequenceOf(
                DerWriter.oid(SHA256_WITH_RSA), DerWriter.nullValue());
        byte[] extensions = authority
                ? DerWriter.explicit(3, DerWriter.sequenceOf(basicConstraints()))
                : new byte[0];
        byte[] tbs = DerWriter.sequenceOf(
                DerWriter.explicit(0, DerWriter.integer(2)),
                DerWriter.integer(serial()),
                algorithm,
                issuer,
                DerWriter.sequenceOf(DerWriter.time(from), DerWriter.time(until)),
                subject,
                publicKeyInfo,
                extensions);
        byte[] certificate = DerWriter.sequenceOf(tbs, algorithm,
                DerWriter.bitString(sign(key, tbs), 0));
        return decode(certificate);
    }

    /** A PKCS#10 for {@code keys}, which is what a server delegating to a
     *  client puts in {@code BUCKET_X509_REQ}. */
    public static byte[] request(KeyPair keys, String cn) {
        byte[] info = DerWriter.sequenceOf(
                DerWriter.integer(0),
                name(cn),
                keys.getPublic().getEncoded(),
                DerWriter.tagged(0xA0, new byte[0]));       // no attributes
        return DerWriter.sequenceOf(info,
                DerWriter.sequenceOf(DerWriter.oid(SHA256_WITH_RSA), DerWriter.nullValue()),
                DerWriter.bitString(sign(keys.getPrivate(), info), 0));
    }

    /** {@code CN=cn}, as a whole distinguished name. */
    public static byte[] name(String cn) {
        return DerWriter.sequenceOf(DerWriter.setOf(DerWriter.sequenceOf(
                DerWriter.oid(COMMON_NAME), DerWriter.printableString(cn))));
    }

    private static byte[] basicConstraints() {
        return DerWriter.sequenceOf(
                DerWriter.oid(BASIC_CONSTRAINTS),
                DerWriter.bool(true),
                DerWriter.octetString(DerWriter.sequenceOf(DerWriter.bool(true))));
    }

    private static BigInteger serial() {
        return BigInteger.valueOf(System.nanoTime() & 0x7FFFFFFFL).add(BigInteger.ONE);
    }

    private static byte[] sign(PrivateKey key, byte[] tbs) {
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(key);
            signer.update(tbs);
            return signer.sign();
        } catch (GeneralSecurityException e) {
            throw new AssertionError("cannot sign a test certificate", e);
        }
    }

    public static X509Certificate decode(byte[] der) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (GeneralSecurityException e) {
            throw new AssertionError("a test certificate will not parse", e);
        }
    }
}

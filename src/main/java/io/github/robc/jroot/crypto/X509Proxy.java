package io.github.robc.jroot.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import io.github.robc.jroot.XrdAuthException;
import io.github.robc.jroot.util.Posix;

/**
 * An X.509 proxy: the chain, its private key, and enough of what the
 * certificates say to fail early and legibly.
 *
 * <p>This deliberately does not verify signatures or build paths. The GSI
 * handshake echoes the chain to the server and the <em>server</em> validates
 * it; what the client needs is to look at the material it is about to offer,
 * so that a proxy which expired an hour ago is a sentence rather than a 3010
 * from the far end.
 */
public final class X509Proxy {

    /** Attribute types {@link javax.security.auth.x500.X500Principal} does not
     *  name, but grid subjects use. */
    private static final Map<String, String> OID_NAMES = Map.of(
            "1.2.840.113549.1.9.1", "emailAddress",
            "2.5.4.5", "serialNumber",
            "0.9.2342.19200300.100.1.1", "UID");

    /** {@code id-pe-proxyCertInfo}: what makes an RFC 3820 proxy a proxy. */
    private static final String PROXY_CERT_INFO_OID = "1.3.6.1.5.5.7.1.14";
    /** The pre-RFC Globus proxy extension, still seen in the wild. */
    private static final String LEGACY_PROXY_OID = "1.3.6.1.4.1.3536.1.222";

    private final List<X509Certificate> chain;
    private final RSAPrivateKey key;
    private final Path path;

    public X509Proxy(List<X509Certificate> chain, RSAPrivateKey key, Path path) {
        if (chain.isEmpty()) {
            throw new XrdAuthException("an X.509 proxy needs at least one certificate");
        }
        this.chain = List.copyOf(chain);
        this.key = key;
        this.path = path;
    }

    /** {@code $X509_USER_PROXY}, else {@code /tmp/x509up_u<uid>}. */
    public static Path defaultPath() {
        String env = System.getenv("X509_USER_PROXY");
        if (env != null && !env.isBlank()) {
            return Path.of(env);
        }
        return Path.of("/tmp/x509up_u" + Posix.uid());
    }

    /** Load a combined proxy file: certificate, private key, issuer chain. */
    public static X509Proxy load(Path path) throws IOException {
        byte[] data = Files.readAllBytes(path);
        List<X509Certificate> certificates = new ArrayList<>();
        CertificateFactory factory;
        try {
            factory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new XrdAuthException("this JVM has no X.509 certificate factory", e);
        }
        for (byte[] der : Pem.blocks(data, "CERTIFICATE")) {
            try {
                certificates.add((X509Certificate)
                        factory.generateCertificate(new ByteArrayInputStream(der)));
            } catch (CertificateException e) {
                // Proxy files routinely carry a CA certificate this reader has
                // no opinion about; one unreadable block must not lose the chain.
            }
        }
        if (certificates.isEmpty()) {
            throw new XrdAuthException("no certificate in " + path);
        }
        return new X509Proxy(certificates, RsaKeys.loadPrivateKey(data), path);
    }

    public List<X509Certificate> chain() {
        return chain;
    }

    /** The end-entity certificate — the proxy itself, first in the file. */
    public X509Certificate certificate() {
        return chain.get(0);
    }

    public RSAPrivateKey key() {
        return key;
    }

    public Path path() {
        return path;
    }

    /** The subject in OpenSSL's oneline form: {@code /DC=org/DC=example/CN=Jane Doe}. */
    public String subject() {
        return oneline(certificate().getSubjectX500Principal().getName(
                javax.security.auth.x500.X500Principal.RFC2253, OID_NAMES));
    }

    /** Who the proxy says you are: the subject with its proxy CNs stripped. */
    public String identity() {
        List<String> rdns = new ArrayList<>(splitRfc2253(
                certificate().getSubjectX500Principal().getName(
                        javax.security.auth.x500.X500Principal.RFC2253, OID_NAMES)));
        // RFC 2253 prints the RDNs in reverse, so the proxy's appended CNs
        // are at the front of this list.
        while (!rdns.isEmpty() && isProxyCn(rdns.get(0))) {
            rdns.remove(0);
        }
        StringBuilder out = new StringBuilder();
        for (int i = rdns.size() - 1; i >= 0; i--) {
            out.append('/').append(rdns.get(i));
        }
        return out.toString();
    }

    private static boolean isProxyCn(String rdn) {
        if (!rdn.startsWith("CN=")) {
            return false;
        }
        String value = rdn.substring(3);
        return value.equals("proxy") || value.equals("limited proxy")
                || value.chars().allMatch(Character::isDigit) && !value.isEmpty();
    }

    /** The certificates of a concatenated PEM chain, in file order. */
    public static List<X509Certificate> parseChain(byte[] pem) {
        List<X509Certificate> out = new ArrayList<>();
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            for (byte[] der : Pem.blocks(pem, "CERTIFICATE")) {
                out.add((X509Certificate)
                        factory.generateCertificate(new ByteArrayInputStream(der)));
            }
        } catch (CertificateException e) {
            throw new XrdAuthException("unreadable certificate chain: " + e.getMessage(), e);
        }
        return out;
    }

    /** Whether the end-entity certificate is a proxy at all. */
    public boolean isProxy() {
        return isProxy(certificate());
    }

    /** Whether {@code cert} is a proxy: it says so, or its subject is its
     *  issuer's with one more name on the end, which is the pre-RFC form. */
    public static boolean isProxy(X509Certificate cert) {
        if (hasExtension(cert, PROXY_CERT_INFO_OID) || hasExtension(cert, LEGACY_PROXY_OID)) {
            return true;
        }
        // A proxy always appends a CN to its issuer's subject; an end-entity
        // certificate from a CA does not.
        List<String> subject = splitRfc2253(cert.getSubjectX500Principal()
                .getName(javax.security.auth.x500.X500Principal.RFC2253, OID_NAMES));
        List<String> issuer = splitRfc2253(cert.getIssuerX500Principal()
                .getName(javax.security.auth.x500.X500Principal.RFC2253, OID_NAMES));
        return subject.size() == issuer.size() + 1
                && subject.subList(1, subject.size()).equals(issuer);
    }

    private static boolean hasExtension(X509Certificate cert, String oid) {
        return (cert.getCriticalExtensionOIDs() != null
                        && cert.getCriticalExtensionOIDs().contains(oid))
                || (cert.getNonCriticalExtensionOIDs() != null
                        && cert.getNonCriticalExtensionOIDs().contains(oid));
    }

    /** When the first certificate in the chain stops being valid. */
    public Instant expiry() {
        Instant earliest = Instant.MAX;
        for (X509Certificate cert : chain) {
            Instant notAfter = cert.getNotAfter().toInstant();
            if (notAfter.isBefore(earliest)) {
                earliest = notAfter;
            }
        }
        return earliest;
    }

    /** Time left before the chain expires; negative once it has. */
    public Duration remaining() {
        return Duration.between(Instant.now(), expiry());
    }

    public boolean isExpired() {
        return !expiry().isAfter(Instant.now());
    }

    /** The chain as concatenated PEM, which is what GSI puts on the wire. */
    public byte[] pem() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (X509Certificate cert : chain) {
            try {
                out.writeBytes(Pem.encode("CERTIFICATE", cert.getEncoded()));
            } catch (CertificateEncodingException e) {
                throw new XrdAuthException("a certificate in " + path + " will not re-encode", e);
            }
        }
        return out.toByteArray();
    }

    /**
     * The chain and key as a one-entry {@link KeyStore}, which is how
     * {@code https://} presents the same proxy as a TLS client certificate.
     * The password is a formality: the store never leaves this process.
     */
    public KeyStore keyStore(char[] password) {
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, password);
            store.setKeyEntry("proxy", key, password, chain.toArray(new X509Certificate[0]));
            return store;
        } catch (java.security.GeneralSecurityException | IOException e) {
            throw new XrdAuthException("cannot build a key store from " + path, e);
        }
    }

    private static String oneline(String rfc2253) {
        List<String> rdns = splitRfc2253(rfc2253);
        StringBuilder out = new StringBuilder();
        for (int i = rdns.size() - 1; i >= 0; i--) {
            out.append('/').append(rdns.get(i));
        }
        return out.toString();
    }

    /** Split on commas that are neither escaped nor inside a quoted value. */
    private static List<String> splitRfc2253(String name) {
        List<String> out = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c == '\\' && i + 1 < name.length()) {
                current.append(c).append(name.charAt(++i));
            } else if (c == '"') {
                quoted = !quoted;
                current.append(c);
            } else if (c == ',' && !quoted) {
                out.add(current.toString().strip());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        if (!current.isEmpty()) {
            out.add(current.toString().strip());
        }
        return out;
    }

    @Override
    public String toString() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("subject", subject());
        fields.put("path", String.valueOf(path));
        return "X509Proxy" + fields;
    }
}

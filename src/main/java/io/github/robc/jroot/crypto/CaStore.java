package io.github.robc.jroot.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import io.github.robc.jroot.XrdAuthException;

/**
 * The grid's trust roots, and what it means to check a chain against them.
 *
 * <p>A CA directory is not a Java trust store. It is a directory of PEM
 * certificates named by subject hash, alongside policy files, CRLs and
 * signing policies this reader has no opinion about, and it is where every
 * grid deployment keeps the certificates that {@code $X509_CERT_DIR} names.
 *
 * <p>The JDK's own path validator cannot be pointed at a GSI chain either: an
 * RFC 3820 proxy carries {@code proxyCertInfo} marked critical, PKIX does not
 * know that extension, and an unknown critical extension is a rejection. So
 * the walk is here — each certificate signed by the next, each inside its
 * validity window, and the top one issued by a root in this store — with the
 * one rule PKIX gets wrong for proxies relaxed deliberately and no other.
 */
public final class CaStore {

    private final Map<X500Principal, List<X509Certificate>> bySubject;
    private final Path source;

    private CaStore(Map<X500Principal, List<X509Certificate>> bySubject, Path source) {
        this.bySubject = bySubject;
        this.source = source;
    }

    /**
     * Where grid trust lives on this machine: {@code $X509_CERT_DIR}, else the
     * conventional location, else nothing — in which case a caller falls back
     * to the JVM's own store, which is right for a commercial CA and useless
     * for a grid one.
     */
    public static Path defaultPath() {
        String env = System.getenv("X509_CERT_DIR");
        if (env != null && !env.isBlank()) {
            return Path.of(env);
        }
        Path conventional = Path.of("/etc/grid-security/certificates");
        return Files.isDirectory(conventional) ? conventional : null;
    }

    /** The store {@code configured} names, or the default location, or
     *  {@code null} when neither exists. */
    public static CaStore discover(Path configured) {
        Path path = configured != null ? configured : defaultPath();
        if (path == null || !Files.exists(path)) {
            return null;
        }
        return load(path);
    }

    /** Every certificate under {@code path}, which may be a file or a
     *  directory. Files that are not certificates are skipped. */
    public static CaStore load(Path path) {
        Map<X500Principal, List<X509Certificate>> bySubject = new LinkedHashMap<>();
        if (Files.isDirectory(path)) {
            try (DirectoryStream<Path> entries = Files.newDirectoryStream(path)) {
                for (Path entry : entries) {
                    if (Files.isRegularFile(entry)) {
                        read(entry, bySubject);
                    }
                }
            } catch (IOException e) {
                throw new XrdAuthException("cannot read the CA directory " + path
                        + ": " + e.getMessage(), e);
            }
        } else {
            read(path, bySubject);
        }
        return new CaStore(bySubject, path);
    }

    private static void read(Path file, Map<X500Principal, List<X509Certificate>> bySubject) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            for (byte[] der : Pem.blocks(Files.readAllBytes(file), "CERTIFICATE")) {
                X509Certificate certificate = (X509Certificate)
                        factory.generateCertificate(new ByteArrayInputStream(der));
                bySubject.computeIfAbsent(certificate.getSubjectX500Principal(),
                        key -> new ArrayList<>()).add(certificate);
            }
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            // A CA directory holds policy files, CRLs and signing_policy as
            // well; anything that will not parse as a certificate is not one.
        }
    }

    public Path source() {
        return source;
    }

    public boolean isEmpty() {
        return bySubject.isEmpty();
    }

    public int size() {
        return bySubject.values().stream().mapToInt(List::size).sum();
    }

    public List<X509Certificate> certificates() {
        List<X509Certificate> out = new ArrayList<>();
        bySubject.values().forEach(out::addAll);
        return out;
    }

    /** The same certificates as a {@link KeyStore}, which is what a
     *  {@code TrustManagerFactory} takes. */
    public KeyStore keyStore() {
        try {
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null, null);
            int index = 0;
            for (X509Certificate certificate : certificates()) {
                store.setCertificateEntry("ca-" + index++, certificate);
            }
            return store;
        } catch (GeneralSecurityException | IOException e) {
            throw new XrdAuthException("cannot build a trust store from " + source, e);
        }
    }

    /**
     * Check that {@code chain} — leaf first, as every X.509 protocol sends it
     * — is currently valid and ends at a root in this store.
     *
     * @param what what the chain belongs to, for the message a failure carries
     * @throws XrdAuthException if it does not, always naming the certificate
     *                          at fault
     */
    public void verify(List<X509Certificate> chain, String what) {
        if (chain.isEmpty()) {
            throw new XrdAuthException(what + " sent no certificate");
        }
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate certificate = chain.get(i);
            checkValidity(certificate, what);
            if (i + 1 < chain.size()) {
                X509Certificate issuer = chain.get(i + 1);
                if (!certificate.getIssuerX500Principal()
                        .equals(issuer.getSubjectX500Principal())) {
                    throw new XrdAuthException(what + "'s chain is broken: "
                            + name(certificate) + " was issued by "
                            + certificate.getIssuerX500Principal().getName()
                            + ", not by " + name(issuer));
                }
                checkSignature(certificate, issuer, what);
                checkAuthority(certificate, issuer, what);
            }
        }
        anchor(chain.get(chain.size() - 1), what);
    }

    /** The root: either the top certificate is one this store holds, or this
     *  store holds the certificate that signed it. */
    private void anchor(X509Certificate top, String what) {
        for (X509Certificate candidate : bySubject.getOrDefault(
                top.getSubjectX500Principal(), List.of())) {
            if (candidate.equals(top)) {
                checkValidity(candidate, "the CA certificate for " + what);
                return;
            }
        }
        List<X509Certificate> issuers =
                bySubject.getOrDefault(top.getIssuerX500Principal(), List.of());
        if (issuers.isEmpty()) {
            throw new XrdAuthException(what + " is signed by "
                    + top.getIssuerX500Principal().getName()
                    + ", which is not in " + source);
        }
        for (X509Certificate issuer : issuers) {
            try {
                top.verify(issuer.getPublicKey());
                checkValidity(issuer, "the CA certificate for " + what);
                return;
            } catch (GeneralSecurityException e) {
                // Two CAs can share a subject across a re-key; try the next.
            }
        }
        throw new XrdAuthException(what + " claims to come from "
                + top.getIssuerX500Principal().getName()
                + ", but no certificate of that name in " + source + " signed it");
    }

    private static void checkValidity(X509Certificate certificate, String what) {
        try {
            certificate.checkValidity();
        } catch (CertificateExpiredException e) {
            throw new XrdAuthException(what + ": " + name(certificate) + " expired at "
                    + certificate.getNotAfter().toInstant());
        } catch (CertificateNotYetValidException e) {
            throw new XrdAuthException(what + ": " + name(certificate)
                    + " is not valid until " + certificate.getNotBefore().toInstant());
        }
    }

    private static void checkSignature(X509Certificate certificate, X509Certificate issuer,
                                       String what) {
        try {
            certificate.verify(issuer.getPublicKey());
        } catch (GeneralSecurityException e) {
            throw new XrdAuthException(what + ": " + name(certificate)
                    + " is not signed by " + name(issuer) + " as it claims");
        }
    }

    /**
     * A certificate that is not a proxy must have been signed by a CA. A
     * proxy must not: it is signed by the end-entity certificate whose
     * identity it carries, which is exactly what makes it a proxy, and
     * demanding the CA bit there is the check PKIX gets wrong.
     */
    private static void checkAuthority(X509Certificate certificate, X509Certificate issuer,
                                       String what) {
        if (X509Proxy.isProxy(certificate)) {
            return;
        }
        if (issuer.getBasicConstraints() < 0) {
            throw new XrdAuthException(what + ": " + name(issuer)
                    + " signed " + name(certificate) + " but is not a certificate authority");
        }
    }

    private static String name(X509Certificate certificate) {
        return certificate.getSubjectX500Principal().getName();
    }

    @Override
    public String toString() {
        return "CaStore[" + source + ", " + size() + " certificates]";
    }
}

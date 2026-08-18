package io.github.robc.jroot.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.robc.jroot.XrdAuthException;

/** Checking a chain against a grid CA directory, proxies and all. */
class CaStoreTest {

    private static KeyPair caKeys;
    private static KeyPair userKeys;
    private static X509Certificate ca;
    private static X509Certificate user;

    @BeforeAll
    static void material() {
        caKeys = Certs.keyPair();
        userKeys = Certs.keyPair();
        ca = Certs.ca(caKeys, "Test CA", Duration.ofDays(365));
        user = Certs.issued(ca, caKeys.getPrivate(), userKeys, "Jane Doe", Duration.ofDays(30));
    }

    private static CaStore store(Path directory, X509Certificate... trusted) throws Exception {
        for (int i = 0; i < trusted.length; i++) {
            Files.write(directory.resolve("root-" + i + ".pem"),
                    Pem.encode("CERTIFICATE", trusted[i].getEncoded()));
        }
        return CaStore.load(directory);
    }

    @Test
    void acceptsAChainThatEndsAtATrustedRoot(@TempDir Path directory) throws Exception {
        CaStore store = store(directory, ca);
        assertEquals(1, store.size());
        store.verify(List.of(user, ca), "the server");
        store.verify(List.of(user), "the server");        // the root need not be sent
    }

    @Test
    void acceptsAProxyEvenThoughItsIssuerIsNoAuthority(@TempDir Path directory) throws Exception {
        // A real RFC 3820 proxy: signed by an end-entity certificate, which is
        // the one thing PKIX will not have.
        X509Proxy identity = new X509Proxy(List.of(user, ca),
                (java.security.interfaces.RSAPrivateKey) userKeys.getPrivate(),
                directory.resolve("x509up"));
        X509Certificate proxy = ProxySigner.sign(identity,
                Certs.request(Certs.keyPair(), "delegate")).certificate();
        assertTrue(X509Proxy.isProxy(proxy));
        store(directory, ca).verify(List.of(proxy, user, ca), "the client");
    }

    @Test
    void refusesAChainNoRootInTheStoreSigned(@TempDir Path directory) throws Exception {
        KeyPair strangerKeys = Certs.keyPair();
        X509Certificate stranger = Certs.ca(strangerKeys, "Some Other CA", Duration.ofDays(10));
        X509Certificate theirs = Certs.issued(stranger, strangerKeys.getPrivate(),
                Certs.keyPair(), "Someone Else", Duration.ofDays(1));
        CaStore store = store(directory, ca);
        XrdAuthException e = assertThrows(XrdAuthException.class,
                () -> store.verify(List.of(theirs, stranger), "the server"));
        assertTrue(e.getMessage().contains("Some Other CA"), e.getMessage());
    }

    @Test
    void refusesAChainThatDoesNotLinkUp(@TempDir Path directory) throws Exception {
        X509Certificate other = Certs.issued(ca, caKeys.getPrivate(), Certs.keyPair(),
                "John Roe", Duration.ofDays(30));
        CaStore store = store(directory, ca);
        XrdAuthException e = assertThrows(XrdAuthException.class,
                () -> store.verify(List.of(user, other, ca), "the server"));
        assertTrue(e.getMessage().contains("chain is broken"), e.getMessage());
    }

    @Test
    void refusesACertificateThatHasExpired(@TempDir Path directory) throws Exception {
        X509Certificate stale = Certs.expired(ca, caKeys.getPrivate(), Certs.keyPair(), "Ghost");
        CaStore store = store(directory, ca);
        XrdAuthException e = assertThrows(XrdAuthException.class,
                () -> store.verify(List.of(stale, ca), "the server"));
        assertTrue(e.getMessage().contains("expired"), e.getMessage());
    }

    @Test
    void refusesAnEndEntityCertificateSignedByAnother(@TempDir Path directory) throws Exception {
        // Not a proxy - a different subject entirely - so its issuer had no
        // business signing it, and PKIX would say the same.
        X509Certificate forged = Certs.issued(user, userKeys.getPrivate(), Certs.keyPair(),
                "Someone Entirely Else", Duration.ofDays(1));
        CaStore store = store(directory, ca);
        XrdAuthException e = assertThrows(XrdAuthException.class,
                () -> store.verify(List.of(forged, user, ca), "the server"));
        assertTrue(e.getMessage().contains("not a certificate authority"), e.getMessage());
    }

    @Test
    void refusesAnEmptyChain(@TempDir Path directory) throws Exception {
        CaStore store = store(directory, ca);
        assertThrows(XrdAuthException.class, () -> store.verify(List.of(), "the server"));
    }

    @Test
    void skipsWhatIsNotACertificate(@TempDir Path directory) throws Exception {
        Files.writeString(directory.resolve("signing_policy"), "access_id_CA X509 'CN=Test CA'\n");
        Files.writeString(directory.resolve("Test.crl_url"), "http://ca.example.org/crl\n");
        CaStore store = store(directory, ca);
        assertEquals(1, store.size());
        store.verify(List.of(user), "the server");
    }

    @Test
    void findsNothingWhereThereIsNothing(@TempDir Path directory) {
        assertNull(CaStore.discover(directory.resolve("no-such-directory")));
    }

    @Test
    void loadsAChainFromASingleFile(@TempDir Path directory) throws Exception {
        Path bundle = directory.resolve("bundle.pem");
        Files.write(bundle, Pem.encode("CERTIFICATE", ca.getEncoded()));
        CaStore store = CaStore.load(bundle);
        assertEquals(1, store.size());
        assertEquals(bundle, store.source());
        store.verify(List.of(user, ca), "the server");
    }
}

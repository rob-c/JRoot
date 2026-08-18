package io.github.robc.jroot.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import io.github.robc.jroot.XrdAuthException;

/** Signing a certificate request into an RFC 3820 proxy, and the DER that takes. */
class DelegationTest {

    private static final String PROXY_CERT_INFO = "1.3.6.1.5.5.7.1.14";

    private static KeyPair caKeys;
    private static KeyPair userKeys;
    private static KeyPair serverKeys;
    private static java.security.cert.X509Certificate ca;
    private static java.security.cert.X509Certificate user;

    @BeforeAll
    static void material() {
        caKeys = Certs.keyPair();
        userKeys = Certs.keyPair();
        serverKeys = Certs.keyPair();
        ca = Certs.ca(caKeys, "Test CA", Duration.ofDays(365));
        user = Certs.issued(ca, caKeys.getPrivate(), userKeys, "Jane Doe", Duration.ofDays(30));
    }

    private static X509Proxy proxy(Duration life) {
        KeyPair proxyKeys = Certs.keyPair();
        var certificate = Certs.issued(user, userKeys.getPrivate(), proxyKeys, "12345", life);
        return new X509Proxy(List.of(certificate, user, ca),
                (RSAPrivateKey) proxyKeys.getPrivate(), Path.of("/tmp/x509up_test"));
    }

    @Test
    void signsARequestIntoAProxyBelowItsParent() {
        X509Proxy parent = proxy(Duration.ofHours(12));
        ProxySigner.Delegated delegated =
                ProxySigner.sign(parent, Certs.request(serverKeys, "ignored"));

        assertEquals(parent.certificate().getSubjectX500Principal(),
                delegated.certificate().getIssuerX500Principal());
        assertEquals(serverKeys.getPublic(), delegated.certificate().getPublicKey());
        assertTrue(X509Proxy.isProxy(delegated.certificate()));
        assertTrue(delegated.certificate().getCriticalExtensionOIDs().contains(PROXY_CERT_INFO));
        // The proxy's own CN is its serial number, which is what makes the
        // subject of a delegated proxy predictable from the certificate.
        assertTrue(delegated.certificate().getSubjectX500Principal().getName()
                .startsWith("CN=" + delegated.certificate().getSerialNumber()));
        assertEquals(4, delegated.chain().size());
    }

    @Test
    void issuesACertificateItsParentSigned() throws Exception {
        X509Proxy parent = proxy(Duration.ofHours(12));
        ProxySigner.Delegated delegated =
                ProxySigner.sign(parent, Certs.request(serverKeys, "server"));
        delegated.certificate().verify(parent.certificate().getPublicKey());
    }

    @Test
    void doesNotOutliveWhatDelegatedIt() {
        X509Proxy parent = proxy(Duration.ofMinutes(20));
        ProxySigner.Delegated delegated =
                ProxySigner.sign(parent, Certs.request(serverKeys, "server"));
        assertFalse(delegated.certificate().getNotAfter().toInstant()
                .isAfter(parent.expiry()));
        assertTrue(delegated.certificate().getNotBefore().toInstant()
                .isBefore(Instant.now()));
    }

    @Test
    void refusesARequestSignedByAnotherKey() {
        byte[] request = Certs.request(serverKeys, "server");
        request[request.length - 1] ^= 0x01;            // one bit of the signature
        X509Proxy parent = proxy(Duration.ofHours(1));
        XrdAuthException e = assertThrows(XrdAuthException.class,
                () -> ProxySigner.sign(parent, request));
        assertTrue(e.getMessage().contains("signed by the key")
                || e.getMessage().contains("unusable certificate request"), e.getMessage());
    }

    @Test
    void refusesToDelegateFromAnExpiredProxy() {
        KeyPair keys = Certs.keyPair();
        X509Proxy parent = new X509Proxy(
                List.of(Certs.expired(user, userKeys.getPrivate(), keys, "12345"), user, ca),
                (RSAPrivateKey) keys.getPrivate(), Path.of("/tmp/x509up_test"));
        XrdAuthException e = assertThrows(XrdAuthException.class,
                () -> ProxySigner.sign(parent, Certs.request(serverKeys, "server")));
        assertTrue(e.getMessage().contains("cannot delegate"), e.getMessage());
    }

    @Test
    void refusesSomethingThatIsNotACertificateRequest() {
        X509Proxy parent = proxy(Duration.ofHours(1));
        assertThrows(XrdAuthException.class,
                () -> ProxySigner.sign(parent, "not DER at all".getBytes()));
    }

    @Test
    void sendsTheWholeChainAsPem() {
        X509Proxy parent = proxy(Duration.ofHours(1));
        ProxySigner.Delegated delegated =
                ProxySigner.sign(parent, Certs.request(serverKeys, "server"));
        List<java.security.cert.X509Certificate> reread =
                X509Proxy.parseChain(delegated.pem());
        assertEquals(delegated.chain(), reread);
    }

    @Test
    void writesDerItsOwnReaderAgreesWith() {
        assertEquals("1.3.6.1.5.5.7.21.1",
                Der.parse(DerWriter.oid("1.3.6.1.5.5.7.21.1")).oid());
        assertEquals(BigInteger.valueOf(300), Der.parse(DerWriter.integer(300)).integer());
        // A length of 400 needs DER's long form, which is where an encoder
        // that only ever saw small values goes wrong.
        assertEquals(400, Der.parse(DerWriter.octetString(new byte[400])).value().length);
        assertEquals(3, Der.sequence(DerWriter.sequenceOf(DerWriter.bool(true),
                DerWriter.nullValue(), DerWriter.printableString("x"))).size());
    }

    @Test
    void datesACertificateTheWayX509Requires() {
        // UTCTime while the two-digit year is unambiguous, GeneralizedTime after.
        assertEquals(0x17, Der.parse(DerWriter.time(Instant.parse("2026-01-01T00:00:00Z"))).tag());
        assertEquals(0x18, Der.parse(DerWriter.time(Instant.parse("2051-01-01T00:00:00Z"))).tag());
    }

    @Test
    void buildsCertificatesTheJdkParsesBack() {
        assertNotNull(ca.getSubjectX500Principal());
        assertEquals("CN=Test CA", ca.getSubjectX500Principal().getName());
        assertEquals("CN=Jane Doe", user.getSubjectX500Principal().getName());
        assertTrue(ca.getBasicConstraints() >= 0, "the CA must carry basicConstraints");
        assertTrue(user.getBasicConstraints() < 0, "an end-entity certificate must not");
    }
}

package io.github.robc.jroot.auth;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.robc.jroot.XrdAuthException;
import io.github.robc.jroot.auth.GsiMessage.Bucket;
import io.github.robc.jroot.crypto.Aes;
import io.github.robc.jroot.crypto.CaStore;
import io.github.robc.jroot.crypto.Certs;
import io.github.robc.jroot.crypto.DerWriter;
import io.github.robc.jroot.crypto.Pem;
import io.github.robc.jroot.crypto.X509Proxy;

/**
 * The GSI steps a server drives: the certificate exchange, and the proxy it
 * may ask the client to sign for it.
 *
 * <p>The server side is played out here in full — a real Diffie-Hellman over
 * a real group, a real PKCS#10, a real AES-encrypted main bucket — because
 * the point of delegation is that both ends agree on a key without either
 * saying so, and only running it proves they did.
 */
class GsiDelegationTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static KeyPair caKeys;
    private static X509Certificate ca;
    private static KeyPair userKeys;
    private static X509Certificate user;

    /** A modest group: the arithmetic is the same at any size, and a small
     *  prime keeps the suite quick. */
    private static BigInteger p;
    private static BigInteger g;
    private static byte[] parameters;

    @BeforeAll
    static void material() {
        caKeys = Certs.keyPair();
        ca = Certs.ca(caKeys, "Test CA", Duration.ofDays(365));
        userKeys = Certs.keyPair();
        user = Certs.issued(ca, caKeys.getPrivate(), userKeys, "Jane Doe", Duration.ofDays(30));
        p = BigInteger.probablePrime(512, RANDOM);
        g = BigInteger.TWO;
        parameters = Pem.encode("DH PARAMETERS",
                DerWriter.sequenceOf(DerWriter.integer(p), DerWriter.integer(g)));
    }

    private static X509Proxy proxy() {
        return new X509Proxy(List.of(user, ca), (RSAPrivateKey) userKeys.getPrivate(),
                Path.of("/tmp/x509up_test"));
    }

    /** The server's half of the exchange, kept so the test can decrypt what
     *  the client sends back. */
    private static final class Server {
        private final BigInteger secret = new BigInteger(120, RANDOM).add(BigInteger.TWO);
        private byte[] sessionKey;

        byte[] certChallenge(byte[] chain) {
            byte[] blob = GsiCredential.publicBlob(parameters, g.modPow(secret, p));
            return GsiMessage.encode(GsiMessage.STEP_SERVER_CERT, List.of(
                    Bucket.of(GsiMessage.BUCKET_CRYPTOMOD, "ssl"),
                    new Bucket(GsiMessage.BUCKET_PUK, blob),
                    new Bucket(GsiMessage.BUCKET_X509, chain),
                    new Bucket(GsiMessage.BUCKET_MAIN, GsiMessage.encode(
                            GsiMessage.STEP_SERVER_CERT,
                            List.of(new Bucket(GsiMessage.BUCKET_RTAG, new byte[8]))))));
        }

        /** Agree the key from what the client answered with. */
        void agree(byte[] response) {
            byte[] blob = GsiMessage.decode(response).find(GsiMessage.BUCKET_PUK);
            assertNotNull(blob, "the client must send its DH public value");
            sessionKey = GsiCredential.sessionKey(GsiCredential.parsePeerBlob(blob), secret);
        }

        byte[] proxyRequest(byte[] pkcs10) {
            return GsiMessage.encode(GsiMessage.STEP_SERVER_PXYREQ, List.of(
                    new Bucket(GsiMessage.BUCKET_MAIN, Aes.cbcEncrypt(sessionKey,
                            GsiMessage.encode(GsiMessage.STEP_SERVER_PXYREQ,
                                    List.of(new Bucket(GsiMessage.BUCKET_X509_REQ, pkcs10)))))));
        }

        List<X509Certificate> signedChain(byte[] reply) {
            GsiMessage.Decoded decoded = GsiMessage.decode(reply);
            assertEquals(GsiMessage.STEP_CLIENT_SIGPXY, decoded.step());
            byte[] inner = Aes.cbcDecrypt(sessionKey, decoded.find(GsiMessage.BUCKET_MAIN));
            return X509Proxy.parseChain(GsiMessage.find(inner, GsiMessage.BUCKET_X509));
        }
    }

    private static GsiCredential credential(CaStore store, boolean delegate) {
        return new GsiCredential(proxy(), "ssl", "", store, delegate);
    }

    private static byte[] serverChain() throws Exception {
        KeyPair hostKeys = Certs.keyPair();
        X509Certificate host = Certs.issued(ca, caKeys.getPrivate(), hostKeys,
                "host/data.example.org", Duration.ofDays(30));
        byte[] first = Pem.encode("CERTIFICATE", host.getEncoded());
        byte[] second = Pem.encode("CERTIFICATE", ca.getEncoded());
        byte[] both = new byte[first.length + second.length];
        System.arraycopy(first, 0, both, 0, first.length);
        System.arraycopy(second, 0, both, first.length, second.length);
        return both;
    }

    private static CaStore store(Path directory, X509Certificate... trusted) throws Exception {
        for (int i = 0; i < trusted.length; i++) {
            Files.write(directory.resolve("root-" + i + ".pem"),
                    Pem.encode("CERTIFICATE", trusted[i].getEncoded()));
        }
        return CaStore.load(directory);
    }

    @Test
    void signsAProxyForAServerThatAsksForOne() throws Exception {
        GsiCredential credential = credential(null, true);
        Server server = new Server();
        credential.initial();
        server.agree(credential.step(server.certChallenge(serverChain())));

        KeyPair serverKeys = Certs.keyPair();
        List<X509Certificate> chain = server.signedChain(
                credential.step(server.proxyRequest(Certs.request(serverKeys, "delegate"))));

        assertEquals(3, chain.size(), "the proxy and the chain it hangs from");
        assertEquals(serverKeys.getPublic(), chain.get(0).getPublicKey());
        assertEquals(user.getSubjectX500Principal(), chain.get(0).getIssuerX500Principal());
        assertTrue(X509Proxy.isProxy(chain.get(0)));
        chain.get(0).verify(user.getPublicKey());
        assertEquals(chain.get(0), credential.delegated().certificate());
    }

    @Test
    void willNotDelegateUnlessItWasToldItMay() throws Exception {
        GsiCredential credential = credential(null, false);
        Server server = new Server();
        credential.initial();
        server.agree(credential.step(server.certChallenge(serverChain())));

        byte[] request = server.proxyRequest(Certs.request(Certs.keyPair(), "delegate"));
        XrdAuthException e = assertThrows(XrdAuthException.class,
                () -> credential.step(request));
        assertTrue(e.getMessage().contains("withDelegateProxy"), e.getMessage());
        assertNull(credential.delegated());
    }

    @Test
    void tellsTheServerUpFrontWhetherItWillSign() {
        int off = options(credential(null, false).initial());
        int on = options(credential(null, true).initial());
        assertEquals(GsiCredential.CLIENT_OPTS_DEFAULT, off);
        assertEquals(GsiCredential.CLIENT_OPTS_DEFAULT | GsiCredential.CLIENT_OPTS_SIGN_DELEGATION,
                on);
    }

    private static int options(byte[] message) {
        byte[] value = GsiMessage.decode(message).find(GsiMessage.BUCKET_CLNT_OPTS);
        assertNotNull(value);
        return ((value[0] & 0xFF) << 24) | ((value[1] & 0xFF) << 16)
                | ((value[2] & 0xFF) << 8) | (value[3] & 0xFF);
    }

    @Test
    void checksTheServersChainAgainstTheCaDirectory(@TempDir Path directory) throws Exception {
        GsiCredential credential = credential(store(directory, ca), true);
        Server server = new Server();
        credential.initial();
        // The whole exchange has to complete for the key to be agreed, which
        // it cannot be if the chain was refused.
        server.agree(credential.step(server.certChallenge(serverChain())));
        assertNotNull(credential.sessionKey());
    }

    @Test
    void refusesAServerWhoseChainAnchorsNowhere(@TempDir Path directory) throws Exception {
        KeyPair strangerKeys = Certs.keyPair();
        X509Certificate stranger = Certs.ca(strangerKeys, "Some Other CA", Duration.ofDays(10));
        GsiCredential credential = credential(store(directory, stranger), true);
        credential.initial();
        byte[] challenge = new Server().certChallenge(serverChain());
        XrdAuthException e = assertThrows(XrdAuthException.class,
                () -> credential.step(challenge));
        assertTrue(e.getMessage().contains("Test CA"), e.getMessage());
        assertNull(credential.sessionKey(), "nothing is agreed with a server that failed to verify");
    }

    @Test
    void takesAServerAtItsWordWhenThereIsNoCaDirectory() throws Exception {
        GsiCredential credential = credential(null, false);
        credential.initial();
        credential.step(new Server().certChallenge(serverChain()));
        assertEquals(GsiCredential.SESSION_KEY_LEN, credential.sessionKey().length);
    }

    @Test
    void refusesSignedDiffieHellmanByName() {
        GsiCredential credential = credential(null, false);
        credential.initial();
        byte[] challenge = GsiMessage.encode(GsiMessage.STEP_SERVER_CERT, List.of(
                Bucket.of(GsiMessage.BUCKET_CRYPTOMOD, "ssl"),
                new Bucket(GsiMessage.BUCKET_CIPHER, new byte[] {1, 2, 3, 4})));
        XrdAuthException e = assertThrows(XrdAuthException.class,
                () -> credential.step(challenge));
        assertTrue(e.getMessage().contains("signed-DH"), e.getMessage());
    }

    @Test
    void refusesAProxyRequestThatCarriesNoRequest() throws Exception {
        GsiCredential credential = credential(null, true);
        Server server = new Server();
        credential.initial();
        server.agree(credential.step(server.certChallenge(serverChain())));
        byte[] empty = GsiMessage.encode(GsiMessage.STEP_SERVER_PXYREQ,
                List.of(new Bucket(GsiMessage.BUCKET_RTAG, new byte[8])));
        XrdAuthException e = assertThrows(XrdAuthException.class,
                () -> credential.step(empty));
        assertTrue(e.getMessage().contains("without sending a certificate request"),
                e.getMessage());
    }

    @Test
    void agreesTheSameKeyAsTheServer() throws Exception {
        GsiCredential credential = credential(null, false);
        Server server = new Server();
        credential.initial();
        server.agree(credential.step(server.certChallenge(serverChain())));
        assertArrayEquals(server.sessionKey, credential.sessionKey());
    }
}

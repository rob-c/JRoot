package io.github.robc.jroot.client;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdConnectionException;
import io.github.robc.jroot.crypto.Pem;
import io.github.robc.jroot.crypto.X509Proxy;

/**
 * The {@link SSLContext} both transports use: the in-protocol TLS upgrade of
 * {@code root://} and the {@code https://} of XRootD-HTTP and WebDAV.
 *
 * <p>Grid trust does not live where the JDK looks, so a CA directory
 * ({@code $X509_CERT_DIR}, conventionally {@code /etc/grid-security/
 * certificates}) is loaded when there is one. An X.509 proxy, when
 * available, is presented as the client certificate — which is what makes
 * GSI-over-HTTPS work at all, since there the mutual TLS handshake
 * <em>is</em> the authentication.
 */
public final class TlsFactory {

    private TlsFactory() {}

    private static final char[] STORE_PASSWORD = "jroot".toCharArray();

    public static SSLContext create(Config config) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagers(config), trustManagers(config), null);
            return context;
        } catch (GeneralSecurityException | IOException e) {
            throw new XrdConnectionException("cannot build a TLS context: " + e.getMessage(), e);
        }
    }

    private static KeyManager[] keyManagers(Config config)
            throws GeneralSecurityException, IOException {
        Path path = config.proxyPath() != null ? config.proxyPath() : X509Proxy.defaultPath();
        if (!Files.isReadable(path)) {
            return null;
        }
        X509Proxy proxy;
        try {
            proxy = X509Proxy.load(path);
        } catch (IOException | RuntimeException e) {
            // A server that wants a client certificate will say so; an
            // unreadable proxy is not a reason to refuse to connect at all.
            return null;
        }
        KeyManagerFactory factory =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(proxy.keyStore(STORE_PASSWORD), STORE_PASSWORD);
        return factory.getKeyManagers();
    }

    private static TrustManager[] trustManagers(Config config)
            throws GeneralSecurityException, IOException {
        if (!config.verifyPeer()) {
            return new TrustManager[] {TRUST_EVERYTHING};
        }
        Path caPath = config.caPath();
        if (caPath == null) {
            String env = System.getenv("X509_CERT_DIR");
            if (env != null && !env.isBlank()) {
                caPath = Path.of(env);
            } else if (Files.isDirectory(Path.of("/etc/grid-security/certificates"))) {
                caPath = Path.of("/etc/grid-security/certificates");
            }
        }
        if (caPath == null || !Files.exists(caPath)) {
            return null;                                  // the JVM's own store
        }
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
        store.load(null, null);
        int loaded = load(caPath, store);
        if (loaded == 0) {
            throw new XrdConnectionException("no CA certificate under " + caPath);
        }
        TrustManagerFactory factory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(store);
        return factory.getTrustManagers();
    }

    private static int load(Path caPath, KeyStore store) throws IOException {
        if (!Files.isDirectory(caPath)) {
            return loadFile(caPath, store, 0);
        }
        int count = 0;
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(caPath)) {
            for (Path entry : entries) {
                if (Files.isRegularFile(entry)) {
                    count = loadFile(entry, store, count);
                }
            }
        }
        return count;
    }

    private static int loadFile(Path file, KeyStore store, int count) {
        // A CA directory holds far more than certificates - policy files,
        // CRLs, signing_policy - so anything that will not parse is skipped
        // rather than fatal.
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            for (byte[] der : Pem.blocks(Files.readAllBytes(file), "CERTIFICATE")) {
                X509Certificate certificate = (X509Certificate)
                        factory.generateCertificate(new ByteArrayInputStream(der));
                store.setCertificateEntry("ca-" + count++, certificate);
            }
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            return count;
        }
        return count;
    }

    /**
     * Accepts any peer. Reachable only through {@code verifyPeer(false)},
     * which exists for a laboratory with a self-signed test server and is
     * never appropriate against real data.
     */
    private static final X509TrustManager TRUST_EVERYTHING = new X509TrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    };
}

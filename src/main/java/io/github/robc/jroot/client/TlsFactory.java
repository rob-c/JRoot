package io.github.robc.jroot.client;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdConnectionException;
import io.github.robc.jroot.crypto.CaStore;
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
        CaStore store = CaStore.discover(config.caPath());
        if (store == null) {
            return null;                                  // the JVM's own store
        }
        if (store.isEmpty()) {
            throw new XrdConnectionException("no CA certificate under " + store.source());
        }
        TrustManagerFactory factory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(store.keyStore());
        return factory.getTrustManagers();
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

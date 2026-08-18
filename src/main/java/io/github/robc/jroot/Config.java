package io.github.robc.jroot;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * Everything a client can be told before it connects. Instances are
 * immutable; each {@code with*} method returns a new configuration, so one
 * base can be shared between connections that differ in a single field.
 */
public final class Config {

    /** When to put the connection inside TLS. */
    public enum Tls {
        /** Upgrade when the server asks for it — the protocol's own rule. */
        AUTO,
        /** Always upgrade, and fail if the server cannot. */
        REQUIRED,
        /** Never upgrade; a server that demands TLS is refused. */
        DISABLED
    }

    private final String username;
    private final String token;
    private final Path proxyPath;
    private final Path caPath;
    private final boolean allowUnix;
    private final boolean verifyPeer;
    private final Tls tls;
    private final List<String> mechanisms;
    private final Duration connectTimeout;
    private final Duration requestTimeout;
    private final int maxRedirects;
    private final int maxWaitSeconds;

    private Config(String username, String token, Path proxyPath, Path caPath,
                   boolean allowUnix, boolean verifyPeer, Tls tls, List<String> mechanisms,
                   Duration connectTimeout, Duration requestTimeout,
                   int maxRedirects, int maxWaitSeconds) {
        this.username = username;
        this.token = token;
        this.proxyPath = proxyPath;
        this.caPath = caPath;
        this.allowUnix = allowUnix;
        this.verifyPeer = verifyPeer;
        this.tls = tls;
        this.mechanisms = List.copyOf(mechanisms);
        this.connectTimeout = connectTimeout;
        this.requestTimeout = requestTimeout;
        this.maxRedirects = maxRedirects;
        this.maxWaitSeconds = maxWaitSeconds;
    }

    /** The defaults: whatever the environment already says, and nothing else. */
    public static Config defaults() {
        return new Config(System.getProperty("user.name", "nobody"), null, null, null,
                true, true, Tls.AUTO, List.of(),
                Duration.ofSeconds(30), Duration.ofMinutes(5), 16, 300);
    }

    public String username() {
        return username;
    }

    public String token() {
        return token;
    }

    public Path proxyPath() {
        return proxyPath;
    }

    /** Where CA certificates live, or {@code null} for the JVM's own store
     *  plus {@code $X509_CERT_DIR}. */
    public Path caPath() {
        return caPath;
    }

    public boolean allowUnix() {
        return allowUnix;
    }

    /** Whether TLS peers are verified. Off is for a lab, never for a grid. */
    public boolean verifyPeer() {
        return verifyPeer;
    }

    public Tls tls() {
        return tls;
    }

    /** Mechanism names to try, most preferred first; empty means the order
     *  the server offered them in. */
    public List<String> mechanisms() {
        return mechanisms;
    }

    public Duration connectTimeout() {
        return connectTimeout;
    }

    public Duration requestTimeout() {
        return requestTimeout;
    }

    public int maxRedirects() {
        return maxRedirects;
    }

    /** The longest {@code kXR_wait} this client will sit out before giving up. */
    public int maxWaitSeconds() {
        return maxWaitSeconds;
    }

    public Config withUsername(String value) {
        return new Config(value, token, proxyPath, caPath, allowUnix, verifyPeer, tls,
                mechanisms, connectTimeout, requestTimeout, maxRedirects, maxWaitSeconds);
    }

    public Config withToken(String value) {
        return new Config(username, value, proxyPath, caPath, allowUnix, verifyPeer, tls,
                mechanisms, connectTimeout, requestTimeout, maxRedirects, maxWaitSeconds);
    }

    public Config withProxyPath(Path value) {
        return new Config(username, token, value, caPath, allowUnix, verifyPeer, tls,
                mechanisms, connectTimeout, requestTimeout, maxRedirects, maxWaitSeconds);
    }

    public Config withCaPath(Path value) {
        return new Config(username, token, proxyPath, value, allowUnix, verifyPeer, tls,
                mechanisms, connectTimeout, requestTimeout, maxRedirects, maxWaitSeconds);
    }

    public Config withAllowUnix(boolean value) {
        return new Config(username, token, proxyPath, caPath, value, verifyPeer, tls,
                mechanisms, connectTimeout, requestTimeout, maxRedirects, maxWaitSeconds);
    }

    public Config withVerifyPeer(boolean value) {
        return new Config(username, token, proxyPath, caPath, allowUnix, value, tls,
                mechanisms, connectTimeout, requestTimeout, maxRedirects, maxWaitSeconds);
    }

    public Config withTls(Tls value) {
        return new Config(username, token, proxyPath, caPath, allowUnix, verifyPeer, value,
                mechanisms, connectTimeout, requestTimeout, maxRedirects, maxWaitSeconds);
    }

    public Config withMechanisms(List<String> value) {
        return new Config(username, token, proxyPath, caPath, allowUnix, verifyPeer, tls,
                value, connectTimeout, requestTimeout, maxRedirects, maxWaitSeconds);
    }

    public Config withConnectTimeout(Duration value) {
        return new Config(username, token, proxyPath, caPath, allowUnix, verifyPeer, tls,
                mechanisms, value, requestTimeout, maxRedirects, maxWaitSeconds);
    }

    public Config withRequestTimeout(Duration value) {
        return new Config(username, token, proxyPath, caPath, allowUnix, verifyPeer, tls,
                mechanisms, connectTimeout, value, maxRedirects, maxWaitSeconds);
    }

    public Config withMaxRedirects(int value) {
        return new Config(username, token, proxyPath, caPath, allowUnix, verifyPeer, tls,
                mechanisms, connectTimeout, requestTimeout, value, maxWaitSeconds);
    }

    public Config withMaxWaitSeconds(int value) {
        return new Config(username, token, proxyPath, caPath, allowUnix, verifyPeer, tls,
                mechanisms, connectTimeout, requestTimeout, maxRedirects, value);
    }

    @Override
    public String toString() {
        return "Config[user=" + username + ", tls=" + tls + ", proxy=" + proxyPath
                + ", token=" + (token == null ? "<discovered>" : "<supplied>") + "]";
    }
}

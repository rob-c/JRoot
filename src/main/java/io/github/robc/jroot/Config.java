package io.github.robc.jroot;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import io.github.robc.jroot.util.Env;
import io.github.robc.jroot.wire.XrdConst;

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
    private final int dataStreams;
    private final boolean delegateProxy;
    private final Path keytab;
    private final Path credentialCache;
    private final String appName;
    private final String clientInfo;
    private final Duration recoveryWindow;

    private Config(Builder builder) {
        this.username = builder.username;
        this.token = builder.token;
        this.proxyPath = builder.proxyPath;
        this.caPath = builder.caPath;
        this.allowUnix = builder.allowUnix;
        this.verifyPeer = builder.verifyPeer;
        this.tls = builder.tls;
        this.mechanisms = List.copyOf(builder.mechanisms);
        this.connectTimeout = builder.connectTimeout;
        this.requestTimeout = builder.requestTimeout;
        this.maxRedirects = builder.maxRedirects;
        this.maxWaitSeconds = builder.maxWaitSeconds;
        this.dataStreams = builder.dataStreams;
        this.delegateProxy = builder.delegateProxy;
        this.keytab = builder.keytab;
        this.credentialCache = builder.credentialCache;
        this.appName = builder.appName;
        this.clientInfo = builder.clientInfo;
        this.recoveryWindow = builder.recoveryWindow;
    }

    /** The defaults: whatever the environment already says, and nothing else. */
    public static Config defaults() {
        return new Builder().build();
    }

    /**
     * The defaults, as the {@code XRD_*} environment already tunes them.
     *
     * <p>A site tunes the reference client by exporting these, and a job
     * inherits the tuning from whatever submitted it. A Java client that
     * ignored them would be quietly slower — or quietly less patient — than
     * every other client on the same worker node, for no reason the operator
     * could see. Anything unset, unreadable or out of range keeps its
     * default rather than failing: the environment is advice.
     */
    public static Config fromEnvironment() {
        Config config = defaults();
        Duration connect = Env.seconds("XRD_CONNECTIONWINDOW");
        if (connect != null) {
            config = config.withConnectTimeout(connect);
        }
        Duration request = Env.seconds("XRD_REQUESTTIMEOUT");
        if (request != null) {
            config = config.withRequestTimeout(request);
        }
        int streams = Env.number("XRD_SUBSTREAMSPERCHANNEL", 1, 16);
        if (streams > 0) {
            config = config.withDataStreams(streams);
        }
        int redirects = Env.number("XRD_REDIRECTLIMIT", 1, 1024);
        if (redirects > 0) {
            config = config.withMaxRedirects(redirects);
        }
        int wait = Env.number("XRD_STREAMTIMEOUT", 1, 86400);
        if (wait > 0) {
            config = config.withMaxWaitSeconds(wait);
        }
        if (Env.flag("XRD_TLSNOVERIFYCERT")) {
            config = config.withVerifyPeer(false);
        }
        int recovery = Env.number("XRD_STREAMERRORWINDOW", 0, 86400);
        if (recovery != Env.UNSET) {
            config = config.withRecoveryWindow(Duration.ofSeconds(recovery));
        }
        String app = Env.text("XRD_APPNAME");
        if (!app.isEmpty()) {
            config = config.withAppName(app);
        }
        String info = Env.text("XRD_INFO");
        if (!info.isEmpty()) {
            config = config.withClientInfo(info);
        }
        return config;
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

    /**
     * How many TCP streams one session may carry data on, the control link
     * included. One — the default — is a single socket and no
     * {@code kXR_bind}; more binds that many less one extra sockets to the
     * session when a file is opened, which is what fills a long fat network
     * that a single stream leaves half idle.
     */
    public int dataStreams() {
        return dataStreams;
    }

    /**
     * Whether this client will sign a proxy for a server that asks for one.
     * Off by default: delegation hands the far end a credential that carries
     * your identity until your own proxy expires, which is a thing to decide
     * rather than a thing to discover.
     */
    public boolean delegateProxy() {
        return delegateProxy;
    }

    /**
     * The {@code sss} keytab, or null to look where the C client looks:
     * {@code $XrdSecSSSKT}, {@code $XrdSecsssKT}, then
     * {@code ~/.xrd/sss.keytab}.
     */
    public Path keytab() {
        return keytab;
    }

    /**
     * The Kerberos credential cache, or null to look where MIT and Heimdal
     * look: {@code $KRB5CCNAME}, then {@code /tmp/krb5cc_<uid>}.
     */
    public Path credentialCache() {
        return credentialCache;
    }

    /**
     * The application name a server records against this session, at most
     * {@value io.github.robc.jroot.client.ClientId#MAX_APPNAME} characters.
     * Sites read it to tell one workload from another; an empty name leaves
     * the field out.
     */
    public String appName() {
        return appName;
    }

    /** Free text sent alongside the application name, at most
     *  {@value io.github.robc.jroot.client.ClientId#MAX_INFO} characters. */
    public String clientInfo() {
        return clientInfo;
    }

    /**
     * How long the client keeps trying to rebuild a session that broke under
     * it before giving the failure to the caller. A minute by default, as
     * {@code $XRD_STREAMERRORWINDOW} sets for the reference client; zero
     * turns recovery off and makes a dropped connection final.
     */
    public Duration recoveryWindow() {
        return recoveryWindow;
    }

    public Config withUsername(String value) {
        return toBuilder().username(value).build();
    }

    public Config withToken(String value) {
        return toBuilder().token(value).build();
    }

    public Config withProxyPath(Path value) {
        return toBuilder().proxyPath(value).build();
    }

    public Config withCaPath(Path value) {
        return toBuilder().caPath(value).build();
    }

    public Config withAllowUnix(boolean value) {
        return toBuilder().allowUnix(value).build();
    }

    public Config withVerifyPeer(boolean value) {
        return toBuilder().verifyPeer(value).build();
    }

    public Config withTls(Tls value) {
        return toBuilder().tls(value).build();
    }

    public Config withMechanisms(List<String> value) {
        return toBuilder().mechanisms(value).build();
    }

    public Config withConnectTimeout(Duration value) {
        return toBuilder().connectTimeout(value).build();
    }

    public Config withRequestTimeout(Duration value) {
        return toBuilder().requestTimeout(value).build();
    }

    public Config withMaxRedirects(int value) {
        return toBuilder().maxRedirects(value).build();
    }

    public Config withMaxWaitSeconds(int value) {
        return toBuilder().maxWaitSeconds(value).build();
    }

    /** Clamped to 1..{@value io.github.robc.jroot.wire.XrdConst#MAX_DATA_PATHS}+1:
     *  a path id is one byte and zero is the control link. */
    public Config withDataStreams(int value) {
        return toBuilder().dataStreams(value).build();
    }

    public Config withDelegateProxy(boolean value) {
        return toBuilder().delegateProxy(value).build();
    }

    public Config withKeytab(Path value) {
        return toBuilder().keytab(value).build();
    }

    public Config withCredentialCache(Path value) {
        return toBuilder().credentialCache(value).build();
    }

    public Config withAppName(String value) {
        return toBuilder().appName(value).build();
    }

    public Config withClientInfo(String value) {
        return toBuilder().clientInfo(value).build();
    }

    public Config withRecoveryWindow(Duration value) {
        return toBuilder().recoveryWindow(value).build();
    }

    /** This configuration, ready to be changed in more than one place at once. */
    public Builder toBuilder() {
        Builder builder = new Builder();
        builder.username = username;
        builder.token = token;
        builder.proxyPath = proxyPath;
        builder.caPath = caPath;
        builder.allowUnix = allowUnix;
        builder.verifyPeer = verifyPeer;
        builder.tls = tls;
        builder.mechanisms = mechanisms;
        builder.connectTimeout = connectTimeout;
        builder.requestTimeout = requestTimeout;
        builder.maxRedirects = maxRedirects;
        builder.maxWaitSeconds = maxWaitSeconds;
        builder.dataStreams = dataStreams;
        builder.delegateProxy = delegateProxy;
        builder.keytab = keytab;
        builder.credentialCache = credentialCache;
        builder.appName = appName;
        builder.clientInfo = clientInfo;
        builder.recoveryWindow = recoveryWindow;
        return builder;
    }

    /**
     * A configuration under construction. Every field starts at the default
     * a bare {@link Config#defaults()} would have, so a builder is worth
     * using directly when several settings change together.
     */
    public static final class Builder {

        private String username = System.getProperty("user.name", "nobody");
        private String token;
        private Path proxyPath;
        private Path caPath;
        private boolean allowUnix = true;
        private boolean verifyPeer = true;
        private Tls tls = Tls.AUTO;
        private List<String> mechanisms = List.of();
        private Duration connectTimeout = Duration.ofSeconds(30);
        private Duration requestTimeout = Duration.ofMinutes(5);
        private int maxRedirects = 16;
        private int maxWaitSeconds = 300;
        private int dataStreams = 1;
        private boolean delegateProxy;
        private Path keytab;
        private Path credentialCache;
        private String appName = "";
        private String clientInfo = "";
        private Duration recoveryWindow = Duration.ofSeconds(60);

        public Builder username(String value) {
            this.username = value;
            return this;
        }

        public Builder token(String value) {
            this.token = value;
            return this;
        }

        public Builder proxyPath(Path value) {
            this.proxyPath = value;
            return this;
        }

        public Builder caPath(Path value) {
            this.caPath = value;
            return this;
        }

        public Builder allowUnix(boolean value) {
            this.allowUnix = value;
            return this;
        }

        public Builder verifyPeer(boolean value) {
            this.verifyPeer = value;
            return this;
        }

        public Builder tls(Tls value) {
            this.tls = value;
            return this;
        }

        public Builder mechanisms(List<String> value) {
            this.mechanisms = value;
            return this;
        }

        public Builder connectTimeout(Duration value) {
            this.connectTimeout = value;
            return this;
        }

        public Builder requestTimeout(Duration value) {
            this.requestTimeout = value;
            return this;
        }

        public Builder maxRedirects(int value) {
            this.maxRedirects = value;
            return this;
        }

        public Builder maxWaitSeconds(int value) {
            this.maxWaitSeconds = value;
            return this;
        }

        public Builder dataStreams(int value) {
            this.dataStreams = Math.max(1, Math.min(value, XrdConst.MAX_DATA_PATHS + 1));
            return this;
        }

        public Builder delegateProxy(boolean value) {
            this.delegateProxy = value;
            return this;
        }

        public Builder keytab(Path value) {
            this.keytab = value;
            return this;
        }

        public Builder credentialCache(Path value) {
            this.credentialCache = value;
            return this;
        }

        public Builder appName(String value) {
            this.appName = value == null ? "" : value;
            return this;
        }

        public Builder clientInfo(String value) {
            this.clientInfo = value == null ? "" : value;
            return this;
        }

        /** Negative is treated as none: a window that has already passed is
         *  the same as not having one. */
        public Builder recoveryWindow(Duration value) {
            this.recoveryWindow = value == null || value.isNegative() ? Duration.ZERO : value;
            return this;
        }

        public Config build() {
            return new Config(this);
        }
    }

    @Override
    public String toString() {
        return "Config[user=" + username + ", tls=" + tls + ", proxy=" + proxyPath
                + ", token=" + (token == null ? "<discovered>" : "<supplied>") + "]";
    }
}

package io.github.robc.jroot.auth;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import com.sun.security.auth.module.Krb5LoginModule;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdAuthException;

/**
 * {@code krb5} — Kerberos 5, against the ticket {@code kinit} left behind.
 *
 * <p>The credential is {@code "krb5\0"} — the NUL-terminated mechanism name
 * every {@code XrdSecInterface} blob starts with — followed by an AP-REQ for
 * the service principal the server names in its offer. The server hands the
 * bytes past that NUL to {@code krb5_rd_req}, which wants the AP-REQ and
 * nothing around it, so the RFC 2743 wrapper the JDK's GSS-API puts on an
 * initial context token is taken off again before the blob goes out.
 *
 * <p>The AP-REQ itself comes from {@code org.ietf.jgss} and the ticket cache
 * comes in through {@code Krb5LoginModule}, both of which ship with the JDK:
 * this stays a client with no dependencies while still letting the KDC's own
 * administrator decide what a valid ticket looks like. That does make
 * {@code krb5} the one mechanism here that may talk to a third party —
 * obtaining a service ticket is a KDC round trip when the cache holds only a
 * TGT. Everything that can be answered without the KDC is answered before
 * then, by {@link Krb5Ccache}: whether there is a ticket, whose it is, and
 * whether it has expired.
 *
 * <p>Not implemented, and refused by name rather than mis-answered: the
 * {@code fwdtgt} round, in which a server asks the client to forward its
 * ticket-granting ticket so the server can act as the user elsewhere. That
 * is credential delegation, it is off by default in the reference server, and
 * a client should not hand over a TGT because a connection asked politely.
 */
public final class Krb5Credential implements Credential {

    /** The name, NUL-terminated, that every credential blob opens with. */
    static final byte[] PREFIX = "krb5\0".getBytes(StandardCharsets.UTF_8);

    /** {@code [APPLICATION 0]}, the tag an RFC 2743 context token opens with. */
    static final int APPLICATION_0 = 0x60;

    /** {@code [APPLICATION 14]}, the tag a bare AP-REQ opens with. */
    static final int AP_REQ = 0x6e;

    static final Oid MECHANISM = oid("1.2.840.113554.1.2.2");
    static final Oid PRINCIPAL_NAME = oid("1.2.840.113554.1.2.2.1");

    /** The service XRootD registers when the offer does not name one. */
    static final String DEFAULT_SERVICE = "xrootd";

    private final String principal;
    private final Subject subject;

    Krb5Credential(String principal, Subject subject) {
        this.principal = principal;
        this.subject = subject;
    }

    @Override
    public String name() {
        return "krb5";
    }

    /** The service principal this asks the KDC for a ticket to. */
    public String principal() {
        return principal;
    }

    @Override
    public byte[] initial() {
        return frame(apReq(advance()));
    }

    /** The mechanism name, its NUL, and then the AP-REQ. */
    static byte[] frame(byte[] apReq) {
        byte[] out = new byte[PREFIX.length + apReq.length];
        System.arraycopy(PREFIX, 0, out, 0, PREFIX.length);
        System.arraycopy(apReq, 0, out, PREFIX.length, apReq.length);
        return out;
    }

    /**
     * There is no second round this client will play. A server that asks
     * again is asking for a forwarded TGT, and the answer is no.
     */
    @Override
    public byte[] step(byte[] challenge) {
        throw new XrdAuthException("the server asked for a forwarded Kerberos ticket-granting"
                + " ticket, which this client does not delegate; turn off fwdtgt on the server"
                + " or authenticate with a mechanism that carries delegation explicitly");
    }

    /** Drive the GSS context one round, as the subject holding the ticket. */
    private byte[] advance() {
        try {
            return Subject.doAs(subject, (PrivilegedExceptionAction<byte[]>) () -> {
                GSSManager manager = GSSManager.getInstance();
                GSSName target = manager.createName(principal, PRINCIPAL_NAME);
                GSSContext context = manager.createContext(target, MECHANISM, null,
                        GSSContext.DEFAULT_LIFETIME);
                context.requestMutualAuth(false);   // the server sends no AP-REP
                return context.initSecContext(new byte[0], 0, 0);
            });
        } catch (PrivilegedActionException e) {
            Throwable cause = e.getCause();
            throw new XrdAuthException("no Kerberos ticket for " + principal + ": "
                    + cause.getMessage(), cause);
        }
    }

    /**
     * The AP-REQ inside an initial context token. GSS-API wraps it in
     * {@code [APPLICATION 0] { mechanism OID, 0x01 0x00, AP-REQ }}; the
     * XRootD server reads what is past the name as an AP-REQ on its own, so
     * the wrapper comes off here. A token that is already bare is passed
     * through, which is what a future JDK returning raw bytes would give.
     */
    static byte[] apReq(byte[] token) {
        if (token.length == 0) {
            throw new XrdAuthException("the Kerberos exchange produced no token");
        }
        if ((token[0] & 0xFF) == AP_REQ) {
            return token;
        }
        if ((token[0] & 0xFF) != APPLICATION_0) {
            throw new XrdAuthException("the Kerberos token starts with 0x"
                    + Integer.toHexString(token[0] & 0xFF)
                    + ", which is neither a context token nor an AP-REQ");
        }
        int at = skipLength(token, 1);
        if (at + 1 >= token.length || (token[at] & 0xFF) != 0x06) {
            throw new XrdAuthException("the Kerberos context token carries no mechanism OID");
        }
        int oidLen = token[at + 1] & 0xFF;
        at += 2;
        if (!hasBytes(token, at, oidLen + 2)) {
            throw new XrdAuthException("the Kerberos context token is truncated at its OID");
        }
        if (!Arrays.equals(token, at, at + oidLen, MECHANISM_DER, 0, MECHANISM_DER.length)) {
            throw new XrdAuthException(
                    "the Kerberos context token is for another mechanism entirely");
        }
        at += oidLen + 2;                           // the OID, then TOK_ID 0x01 0x00
        byte[] out = new byte[token.length - at];
        System.arraycopy(token, at, out, 0, out.length);
        return out;
    }

    /** The DER encoding of the krb5 mechanism OID, without its tag. */
    private static final byte[] MECHANISM_DER = {
        0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x12, 0x01, 0x02, 0x02
    };

    /** Step over a DER length at {@code at}, returning where the value starts. */
    private static int skipLength(byte[] der, int at) {
        if (at >= der.length) {
            throw new XrdAuthException("the Kerberos context token has no length");
        }
        int first = der[at] & 0xFF;
        if (first < 0x80) {
            return at + 1;
        }
        int count = first & 0x7F;
        if (count == 0 || count > 4 || !hasBytes(der, at + 1, count)) {
            throw new XrdAuthException("the Kerberos context token has an unreadable length");
        }
        return at + 1 + count;
    }

    private static boolean hasBytes(byte[] bytes, int at, int count) {
        return at >= 0 && count >= 0 && at + count <= bytes.length;
    }

    /**
     * Build a {@code krb5} credential, or empty when there is no ticket to
     * build one from. A cache that exists but holds nothing live is named
     * out loud: "your ticket expired" is a thing the user can act on, where
     * falling silently through to {@code unix} is not.
     */
    public static Optional<Krb5Credential> available(SecurityOffer offer, Config config,
                                                     String host) {
        Path path = config.credentialCache() != null
                ? config.credentialCache() : Krb5Ccache.defaultPath();
        if (!Files.isRegularFile(path)) {
            return Optional.empty();
        }
        List<Krb5Ccache.Ticket> live = Krb5Ccache.tickets(path);
        if (live.isEmpty()) {
            throw new XrdAuthException("the Kerberos credential cache " + path
                    + " holds no unexpired ticket; run kinit");
        }
        return Optional.of(new Krb5Credential(servicePrincipal(offer, host),
                login(path, live.get(0).client().toString())));
    }

    /**
     * The principal to ask for a ticket to. The server names it in its offer
     * and the convention is {@code xrootd/<host>} when it does not. The realm
     * is dropped: Kerberos derives it from the instance, and a stale realm in
     * a server's offer is a well-worn way to fail confusingly.
     */
    static String servicePrincipal(SecurityOffer offer, String host) {
        String named = offer.params().isBlank() ? "" : offer.params().split(",")[0].strip();
        if (named.isEmpty() || named.contains(":")) {
            named = host == null || host.isBlank() ? DEFAULT_SERVICE : DEFAULT_SERVICE + "/" + host;
        }
        int at = named.indexOf('@');
        return at < 0 ? named : named.substring(0, at);
    }

    /**
     * A subject holding whatever is in {@code path}. The login module reads
     * the cache and prompts for nothing: this is a client picking up a ticket
     * that is already there, not one asking for a password.
     */
    private static Subject login(Path path, String client) {
        Subject subject = new Subject();
        Map<String, String> options = new HashMap<>();
        options.put("useTicketCache", "true");
        options.put("ticketCache", path.toString());
        options.put("doNotPrompt", "true");
        options.put("useKeyTab", "false");
        options.put("renewTGT", "false");
        options.put("principal", client);
        Krb5LoginModule module = new Krb5LoginModule();
        module.initialize(subject, null, new HashMap<>(), options);
        try {
            module.login();
            module.commit();
        } catch (LoginException e) {
            throw new XrdAuthException("the Kerberos credential cache " + path
                    + " would not yield a ticket for " + client + ": " + e.getMessage(), e);
        }
        return subject;
    }

    private static Oid oid(String value) {
        try {
            return new Oid(value);
        } catch (GSSException e) {
            throw new IllegalStateException(value + " is not an OID", e);
        }
    }

    @Override
    public String toString() {
        return "Krb5Credential[" + principal + "]";
    }
}

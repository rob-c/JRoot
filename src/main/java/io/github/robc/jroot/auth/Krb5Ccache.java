package io.github.robc.jroot.auth;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import io.github.robc.jroot.XrdAuthException;
import io.github.robc.jroot.util.Posix;
import io.github.robc.jroot.wire.RBuf;

/**
 * The Kerberos credential cache {@code kinit} writes, read for what it can
 * answer without a KDC.
 *
 * <p>Nothing here mints a credential — that is {@link Krb5Credential}'s work,
 * and it goes through the JDK's own Kerberos. What this reads is the state of
 * the cache: whether there is a ticket at all, whose it is, and when it runs
 * out. That is the difference between "authentication failed" and "your
 * Kerberos ticket expired 40 minutes ago", and it costs one file read before
 * anything touches the network.
 *
 * <p>The FILE format is versions 3 and 4, which is what MIT and Heimdal
 * write: a version, an optional header, the cache's own principal, then one
 * entry per ticket. An entry that will not parse ends the scan rather than
 * failing the read, because a cache being rewritten underneath us should cost
 * its tail and not the tickets already recovered.
 */
public final class Krb5Ccache {

    private static final int VERSION_3 = 0x0503;
    private static final int VERSION_4 = 0x0504;

    private Krb5Ccache() {}

    /** A principal: its components and the realm they belong to. */
    public record Principal(List<String> components, String realm, int nameType) {

        @Override
        public String toString() {
            String name = String.join("/", components);
            return realm.isEmpty() ? name : name + "@" + realm;
        }
    }

    /** One cached ticket. The session key is deliberately not kept. */
    public record Ticket(Principal client, Principal server, int encryptionType,
                         long authTime, long startTime, long endTime, long renewTill) {

        public boolean isExpired() {
            return endTime <= Instant.now().getEpochSecond();
        }

        /** Seconds left, or zero once it has run out. */
        public long remaining() {
            return Math.max(0, endTime - Instant.now().getEpochSecond());
        }

        /** The ticket-granting ticket, {@code krbtgt/REALM@REALM}. */
        public boolean isTicketGranting() {
            return !server.components().isEmpty()
                    && server.components().get(0).equals("krbtgt");
        }

        @Override
        public String toString() {
            return "Krb5Ccache.Ticket[" + server + ", expires in " + remaining() + "s]";
        }
    }

    /** A cache's default principal and every ticket in it, expired or not. */
    public record Cache(Principal principal, List<Ticket> tickets) {}

    /**
     * {@code $KRB5CCNAME} without its {@code FILE:} prefix, else
     * {@code /tmp/krb5cc_<uid>}. A cache type this cannot read — a
     * {@code KEYRING:} or {@code KCM:} name — is not a file, so it is
     * reported as such rather than opened.
     */
    public static Path defaultPath() {
        return defaultPath(System.getenv("KRB5CCNAME"));
    }

    /** {@link #defaultPath()}, with the environment handed in. */
    static Path defaultPath(String name) {
        if (name == null || name.isBlank()) {
            return Path.of("/tmp/krb5cc_" + Posix.uid());
        }
        if (name.startsWith("FILE:")) {
            return Path.of(name.substring(5));
        }
        if (name.contains(":")) {
            throw new XrdAuthException("$KRB5CCNAME names " + name
                    + ", which is not a file this client can read; point it at a FILE: cache");
        }
        return Path.of(name);
    }

    /** Every unexpired ticket in {@code path}, or none if it cannot be read. */
    public static List<Ticket> tickets(Path path) {
        try {
            return read(path).tickets().stream().filter(ticket -> !ticket.isExpired()).toList();
        } catch (XrdAuthException | UncheckedIOException e) {
            return List.of();
        }
    }

    public static Cache read(Path path) {
        byte[] bytes;
        try {
            bytes = Files.readAllBytes(path);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return parse(bytes, path);
    }

    static Cache parse(byte[] bytes, Path path) {
        RBuf r = new RBuf(bytes, "Kerberos credential cache " + path);
        int version = r.u16();
        if (version != VERSION_3 && version != VERSION_4) {
            throw new XrdAuthException(path + " is not a credential cache this client reads:"
                    + " version 0x" + Integer.toHexString(version)
                    + ", where MIT and Heimdal write 0x503 or 0x504");
        }
        if (version == VERSION_4) {
            r.skip(r.u16());                        // header tags, none of them ours
        }
        Principal principal = principal(r);
        List<Ticket> tickets = new ArrayList<>();
        while (r.remaining() > 0) {
            try {
                tickets.add(entry(r, version));
            } catch (RuntimeException e) {
                break;                              // a cache rewritten under us
            }
        }
        return new Cache(principal, tickets);
    }

    private static Ticket entry(RBuf r, int version) {
        Principal client = principal(r);
        Principal server = principal(r);
        int encryptionType = r.u16();
        if (version == VERSION_3) {
            r.u16();                                // version 3 wrote it twice
        }
        blob(r);                                    // the session key stays here
        long authTime = r.u32();
        long startTime = r.u32();
        long endTime = r.u32();
        long renewTill = r.u32();
        r.skip(1);                                  // is_skey
        r.u32();                                    // ticket flags
        for (int i = (int) r.u32(); i > 0; i--) {   // addresses
            r.u16();
            blob(r);
        }
        for (int i = (int) r.u32(); i > 0; i--) {   // authorization data
            r.u16();
            blob(r);
        }
        blob(r);                                    // the ticket itself
        blob(r);                                    // second ticket, user-to-user only
        return new Ticket(client, server, encryptionType,
                authTime, startTime, endTime, renewTill);
    }

    private static Principal principal(RBuf r) {
        int nameType = (int) r.u32();
        int count = (int) r.u32();
        String realm = text(r);
        List<String> components = new ArrayList<>(Math.max(count, 0));
        for (int i = 0; i < count; i++) {
            components.add(text(r));
        }
        return new Principal(List.copyOf(components), realm, nameType);
    }

    private static byte[] blob(RBuf r) {
        return r.bytes((int) r.u32());
    }

    private static String text(RBuf r) {
        return new String(blob(r), StandardCharsets.UTF_8);
    }
}

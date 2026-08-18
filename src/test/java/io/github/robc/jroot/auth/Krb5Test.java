package io.github.robc.jroot.auth;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdAuthException;
import io.github.robc.jroot.util.Posix;

/**
 * {@code krb5}: the credential cache, the service principal, and the framing
 * the blob goes out in.
 *
 * <p>What is not here is an AP-REQ. Minting one means a KDC, and a Kerberos
 * exchange whose only witness is its own decoder would be worth less than
 * none: the token itself comes from the JDK's GSS-API, which the KDC's
 * administrator already tests against. Everything on either side of that
 * call is this client's own work, and all of it is below.
 */
class Krb5Test {

    private static final HexFormat HEX = HexFormat.of();

    private static final long HOUR = 3600L;

    // -----------------------------------------------------------------
    // The credential cache
    // -----------------------------------------------------------------

    @Test
    void readsAPrincipalAndTheTicketsUnderIt(@TempDir Path directory) throws Exception {
        long now = Instant.now().getEpochSecond();
        Path path = cache(directory, 0x0504, "alice", "EXAMPLE.ORG",
                ticket("krbtgt/EXAMPLE.ORG", now + HOUR),
                ticket("xrootd/store.example.org", now + HOUR));

        Krb5Ccache.Cache cache = Krb5Ccache.read(path);
        assertEquals("alice@EXAMPLE.ORG", cache.principal().toString());
        assertEquals(2, cache.tickets().size());
        assertEquals("krbtgt/EXAMPLE.ORG@EXAMPLE.ORG", cache.tickets().get(0).server().toString());
        assertTrue(cache.tickets().get(0).isTicketGranting());
        assertFalse(cache.tickets().get(1).isTicketGranting());
        assertEquals(18, cache.tickets().get(0).encryptionType());
    }

    @Test
    void readsTheOlderCacheFormatWhereTheEnctypeIsWrittenTwice(@TempDir Path directory)
            throws Exception {
        long now = Instant.now().getEpochSecond();
        Path path = cache(directory, 0x0503, "bob", "EXAMPLE.ORG",
                ticket("krbtgt/EXAMPLE.ORG", now + HOUR));

        Krb5Ccache.Cache cache = Krb5Ccache.read(path);
        assertEquals("bob@EXAMPLE.ORG", cache.principal().toString());
        assertEquals(1, cache.tickets().size());
        assertEquals("bob@EXAMPLE.ORG", cache.tickets().get(0).client().toString());
    }

    @Test
    void keepsOnlyTheTicketsThatHaveNotRunOut(@TempDir Path directory) throws Exception {
        long now = Instant.now().getEpochSecond();
        Path path = cache(directory, 0x0504, "alice", "EXAMPLE.ORG",
                ticket("krbtgt/EXAMPLE.ORG", now - HOUR),
                ticket("xrootd/store.example.org", now + HOUR));

        assertEquals(2, Krb5Ccache.read(path).tickets().size());
        List<Krb5Ccache.Ticket> live = Krb5Ccache.tickets(path);
        assertEquals(1, live.size());
        assertEquals("xrootd/store.example.org@EXAMPLE.ORG", live.get(0).server().toString());
        assertTrue(live.get(0).remaining() > 0);
        assertEquals(0, Krb5Ccache.read(path).tickets().get(0).remaining());
    }

    @Test
    void keepsTheTicketsItReadWhenTheCacheIsRewrittenUnderIt(@TempDir Path directory)
            throws Exception {
        long now = Instant.now().getEpochSecond();
        Path path = cache(directory, 0x0504, "alice", "EXAMPLE.ORG",
                ticket("krbtgt/EXAMPLE.ORG", now + HOUR),
                ticket("xrootd/store.example.org", now + HOUR));
        byte[] whole = Files.readAllBytes(path);
        Files.write(path, Arrays.copyOf(whole, whole.length - 24));

        Krb5Ccache.Cache cache = Krb5Ccache.read(path);
        assertEquals(1, cache.tickets().size());
        assertTrue(cache.tickets().get(0).isTicketGranting());
    }

    @Test
    void refusesAFileThatIsNotACredentialCache(@TempDir Path directory) throws Exception {
        Path path = directory.resolve("not-a-cache");
        Files.write(path, HEX.parseHex("0001000000000000"));

        XrdAuthException e = assertThrows(XrdAuthException.class, () -> Krb5Ccache.read(path));
        assertTrue(e.getMessage().contains("0x1"), e.getMessage());
        assertTrue(Krb5Ccache.tickets(path).isEmpty());
    }

    @Test
    void readsNoTicketsFromACacheThatIsNotThere(@TempDir Path directory) {
        Path absent = directory.resolve("absent");
        assertTrue(Krb5Ccache.tickets(absent).isEmpty());
        assertThrows(UncheckedIOException.class, () -> Krb5Ccache.read(absent));
    }

    @Test
    void looksWhereTheEnvironmentPointsAndSaysSoWhenItCannot() {
        assertEquals(Path.of("/tmp/krb5cc_" + Posix.uid()), Krb5Ccache.defaultPath(null));
        assertEquals(Path.of("/tmp/krb5cc_" + Posix.uid()), Krb5Ccache.defaultPath("  "));
        assertEquals(Path.of("/run/user/1000/krb5cc"),
                Krb5Ccache.defaultPath("FILE:/run/user/1000/krb5cc"));
        assertEquals(Path.of("/run/user/1000/krb5cc"),
                Krb5Ccache.defaultPath("/run/user/1000/krb5cc"));

        XrdAuthException e = assertThrows(XrdAuthException.class,
                () -> Krb5Ccache.defaultPath("KEYRING:persistent:1000"));
        assertTrue(e.getMessage().contains("FILE:"), e.getMessage());
    }

    // -----------------------------------------------------------------
    // The service principal
    // -----------------------------------------------------------------

    @Test
    void asksForTheTicketTheServerNames() {
        assertEquals("xrootd/store.example.org", principal("krb5,xrootd/store.example.org"));
        assertEquals("host/store.example.org", principal("krb5,host/store.example.org"));
    }

    @Test
    void dropsTheRealmTheOfferCameWith() {
        assertEquals("xrootd/store.example.org",
                principal("krb5,xrootd/store.example.org@EXAMPLE.ORG"));
    }

    @Test
    void namesTheServiceAfterTheHostWhenTheOfferDoesNot() {
        assertEquals("xrootd/store.example.org", principal("krb5"));
        assertEquals("xrootd/store.example.org", principal("krb5,ver:1"));
        assertEquals("xrootd", Krb5Credential.servicePrincipal(
                SecurityOffer.parse("&P=krb5").get(0), ""));
    }

    // -----------------------------------------------------------------
    // The blob
    // -----------------------------------------------------------------

    @Test
    void takesTheApReqOutOfAContextToken() {
        byte[] apReq = HEX.parseHex("6e0201006e820104");
        assertArrayEquals(apReq, Krb5Credential.apReq(contextToken(apReq)));
    }

    @Test
    void readsALongFormLengthOnTheWayPast() {
        byte[] apReq = new byte[300];
        apReq[0] = 0x6e;
        Arrays.fill(apReq, 1, apReq.length, (byte) 0x41);
        byte[] token = contextToken(apReq);
        assertEquals(0x82, token[1] & 0xFF);
        assertArrayEquals(apReq, Krb5Credential.apReq(token));
    }

    @Test
    void leavesATokenThatIsAlreadyAnApReqAlone() {
        byte[] apReq = HEX.parseHex("6e820104a003020105");
        assertArrayEquals(apReq, Krb5Credential.apReq(apReq));
    }

    @Test
    void refusesATokenForSomeOtherMechanismEntirely() {
        byte[] spnego = HEX.parseHex("60160604062b0601050502a00c300a30080606"
                + "2b06010505020a");
        XrdAuthException e = assertThrows(XrdAuthException.class,
                () -> Krb5Credential.apReq(spnego));
        assertTrue(e.getMessage().contains("another mechanism"), e.getMessage());
    }

    @Test
    void refusesTokensItCannotMakeSenseOf() {
        assertThrows(XrdAuthException.class, () -> Krb5Credential.apReq(new byte[0]));
        assertThrows(XrdAuthException.class, () -> Krb5Credential.apReq(HEX.parseHex("3003020101")));
        assertThrows(XrdAuthException.class, () -> Krb5Credential.apReq(HEX.parseHex("6002")));
        assertThrows(XrdAuthException.class, () -> Krb5Credential.apReq(HEX.parseHex("60ff01")));
        assertThrows(XrdAuthException.class,
                () -> Krb5Credential.apReq(HEX.parseHex("6006050403020100")));
    }

    @Test
    void putsTheMechanismNameAndItsNulInFrontOfTheApReq() {
        byte[] blob = Krb5Credential.frame(HEX.parseHex("6e0201"));
        assertArrayEquals(HEX.parseHex("6b726235006e0201"), blob);
        assertEquals("krb5", new String(blob, 0, 4, StandardCharsets.UTF_8));
    }

    @Test
    void willNotForwardTheTicketThatGrantsTheOthers() {
        Krb5Credential credential = new Krb5Credential("xrootd/store.example.org", null);
        assertEquals("krb5", credential.name());
        assertEquals("xrootd/store.example.org", credential.principal());
        XrdAuthException e = assertThrows(XrdAuthException.class,
                () -> credential.step(new byte[] {1}));
        assertTrue(e.getMessage().contains("fwdtgt"), e.getMessage());
        assertEquals(null, credential.sessionKey());
    }

    // -----------------------------------------------------------------
    // The ladder
    // -----------------------------------------------------------------

    @Test
    void sitsOutWhenThereIsNoCacheAtAll(@TempDir Path directory) {
        Config config = Config.defaults().withCredentialCache(directory.resolve("absent"));
        CredentialLadder ladder = CredentialLadder.build(
                SecurityOffer.parse("&P=krb5,xrootd/store.example.org&P=unix"),
                config, "store.example.org");

        assertEquals("unix", ladder.candidates().get(0).credential().name());
        assertTrue(ladder.rejections().get("krb5").contains("no Kerberos credential cache"),
                ladder.explain());
    }

    @Test
    void saysTheTicketExpiredRatherThanFailingLater(@TempDir Path directory) throws Exception {
        long now = Instant.now().getEpochSecond();
        Path path = cache(directory, 0x0504, "alice", "EXAMPLE.ORG",
                ticket("krbtgt/EXAMPLE.ORG", now - HOUR));
        Config config = Config.defaults().withCredentialCache(path).withAllowUnix(false);
        CredentialLadder ladder = CredentialLadder.build(
                SecurityOffer.parse("&P=krb5&P=unix"), config, "store.example.org");

        assertTrue(ladder.isEmpty());
        assertTrue(ladder.explain().contains("run kinit"), ladder.explain());
    }

    // -----------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------

    private static String principal(String clause) {
        return Krb5Credential.servicePrincipal(
                SecurityOffer.parse("&P=" + clause).get(0), "store.example.org");
    }

    /** An RFC 2743 initial context token around {@code apReq}. */
    private static byte[] contextToken(byte[] apReq) {
        byte[] oid = HEX.parseHex("06092a864886f712010202");
        byte[] body = new byte[oid.length + 2 + apReq.length];
        System.arraycopy(oid, 0, body, 0, oid.length);
        body[oid.length] = 0x01;
        System.arraycopy(apReq, 0, body, oid.length + 2, apReq.length);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x60);
        if (body.length < 0x80) {
            out.write(body.length);
        } else {
            out.write(0x82);
            out.write(body.length >> 8);
            out.write(body.length & 0xFF);
        }
        out.writeBytes(body);
        return out.toByteArray();
    }

    /** One entry, described by the service it is for and when it runs out. */
    private record Entry(String service, long endTime) {}

    private static Entry ticket(String service, long endTime) {
        return new Entry(service, endTime);
    }

    /** A FILE credential cache of the given version, written out. */
    private static Path cache(Path directory, int version, String user, String realm,
                              Entry... entries) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        out.writeShort(version);
        if (version == 0x0504) {
            out.writeShort(12);                             // one DeltaTime header tag
            out.writeShort(1);
            out.writeShort(8);
            out.writeLong(0);
        }
        principal(out, user, realm);
        for (Entry entry : entries) {
            principal(out, user, realm);
            principal(out, entry.service(), realm);
            out.writeShort(18);                             // aes256-cts-hmac-sha1-96
            if (version == 0x0503) {
                out.writeShort(18);
            }
            blob(out, new byte[32]);                        // the session key
            long start = entry.endTime() - 10 * HOUR;
            out.writeInt((int) start);
            out.writeInt((int) start);
            out.writeInt((int) entry.endTime());
            out.writeInt(0);                                // renew till
            out.writeByte(0);                               // is_skey
            out.writeInt(0x50e00000);                       // ticket flags
            out.writeInt(0);                                // addresses
            out.writeInt(0);                                // authorization data
            blob(out, "a ticket, DER, which nothing here decodes"
                    .getBytes(StandardCharsets.UTF_8));
            blob(out, new byte[0]);                         // second ticket
        }
        Path path = directory.resolve("krb5cc_test");
        Files.write(path, bytes.toByteArray());
        return path;
    }

    private static void principal(DataOutputStream out, String name, String realm)
            throws IOException {
        String[] components = name.split("/");
        out.writeInt(1);                                    // KRB5_NT_PRINCIPAL
        out.writeInt(components.length);
        blob(out, realm.getBytes(StandardCharsets.UTF_8));
        for (String component : components) {
            blob(out, component.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static void blob(DataOutputStream out, byte[] value) throws IOException {
        out.writeInt(value.length);
        out.write(value);
    }
}

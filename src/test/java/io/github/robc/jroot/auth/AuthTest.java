package io.github.robc.jroot.auth;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import io.github.robc.jroot.XrdAuthException;

/** Credentials and the GSI bucket frame they travel in. */
class AuthTest {

    // -----------------------------------------------------------------
    // The server's security offer
    // -----------------------------------------------------------------

    @Test
    void readsTheProtocolsAServerOffers() {
        List<SecurityOffer> offers = SecurityOffer.parse(
                "&P=gsi,v:10400,c:ssl,ca:5168b7eb.0|8b8c8d8e.0&P=ztn,p:1&P=unix");
        assertEquals(List.of("gsi", "ztn", "unix"),
                offers.stream().map(SecurityOffer::name).toList());
        assertEquals("10400", offers.get(0).options().get("v"));
        assertEquals("5168b7eb.0|8b8c8d8e.0", offers.get(0).options().get("ca"));
        assertEquals("1", offers.get(1).options().get("p"));
        assertTrue(offers.get(2).options().isEmpty());
    }

    @Test
    void survivesAnEmptyOrOddSecurityString() {
        assertTrue(SecurityOffer.parse("").isEmpty());
        assertTrue(SecurityOffer.parse("&P=").isEmpty());
        assertEquals("unix", SecurityOffer.parse("P=unix").get(0).name());
    }

    // -----------------------------------------------------------------
    // unix
    // -----------------------------------------------------------------

    @Test
    void sendsTheUserAndGroupAsUnixCredentials() {
        UnixCredential credential = new UnixCredential("rcurrie", "atlas");
        assertEquals("unix", credential.name());
        assertEquals("unix\0rcurrie atlas",
                new String(credential.initial(), StandardCharsets.US_ASCII));
        assertTrue(new String(UnixCredential.ofCurrentUser().initial(),
                StandardCharsets.US_ASCII).startsWith("unix\0"));
    }

    // -----------------------------------------------------------------
    // ztn
    // -----------------------------------------------------------------

    @Test
    void framesABearerTokenForZtn() {
        TokenCredential credential = new TokenCredential("  header.body.signature  ");
        assertEquals("ztn", credential.name());
        assertEquals("header.body.signature", credential.token(), "stripped of whitespace");
        byte[] initial = credential.initial();
        assertEquals("ztn\0", new String(initial, 0, 4, StandardCharsets.US_ASCII));
        assertEquals("header.body.signature",
                new String(initial, 4, initial.length - 4, StandardCharsets.US_ASCII));
    }

    @Test
    void readsTheExpiryOfAJwtWithoutVerifyingIt() {
        long expiry = Instant.now().plusSeconds(3600).getEpochSecond();
        String token = jwt("{\"sub\":\"rcurrie\",\"exp\":" + expiry + ",\"scope\":\"read\"}");
        assertEquals(Optional.of(Instant.ofEpochSecond(expiry)),
                TokenCredential.expiryOf(token));
        assertEquals(Instant.ofEpochSecond(expiry),
                new TokenCredential(token).expiry().orElseThrow());
    }

    @Test
    void treatsATokenWithNoReadableExpiryAsOpenEnded() {
        assertTrue(TokenCredential.expiryOf("not-a-jwt").isEmpty());
        assertTrue(TokenCredential.expiryOf(jwt("{\"sub\":\"rcurrie\"}")).isEmpty());
        assertTrue(TokenCredential.expiryOf(jwt("{\"exp\":\"soon\"}")).isEmpty());
        assertTrue(TokenCredential.expiryOf("a.!!!not base64!!!.c").isEmpty());
        assertTrue(new TokenCredential("opaque-macaroon").expiry().isEmpty());
    }

    @Test
    void refusesToSendATokenThatHasAlreadyExpired() {
        String token = jwt("{\"exp\":" + (Instant.now().getEpochSecond() - 60) + "}");
        TokenCredential credential = new TokenCredential(token);
        XrdAuthException failure =
                assertThrows(XrdAuthException.class, credential::initial);
        assertTrue(failure.getMessage().contains("expired"));
    }

    @Test
    void keepsTheTokenOutOfItsOwnToString() {
        assertFalse(new TokenCredential("secret-token").toString().contains("secret-token"));
    }

    @Test
    void checksTheLimitsTheServerStatedBeforeSendingAnything() {
        SecurityOffer offer = SecurityOffer.parse("&P=ztn,3600:64:").get(0);
        assertTrue(TokenCredential.available(offer, "short-enough").isPresent());

        XrdAuthException tooLong = assertThrows(XrdAuthException.class,
                () -> TokenCredential.available(offer, "x".repeat(65)));
        assertTrue(tooLong.getMessage().contains("at most 64"));

        String expiringSoon = jwt("{\"exp\":" + (Instant.now().getEpochSecond() + 60) + "}");
        XrdAuthException tooShort = assertThrows(XrdAuthException.class,
                () -> TokenCredential.available(offer, expiringSoon));
        assertTrue(tooShort.getMessage().contains("3600s of life"));
    }

    @Test
    void ignoresOfferParametersItCannotRead() {
        // Old servers put a version string where the limits now go.
        SecurityOffer offer = SecurityOffer.parse("&P=ztn,p:1").get(0);
        assertTrue(TokenCredential.available(offer, "x".repeat(4096)).isPresent());
    }

    // -----------------------------------------------------------------
    // GSI bucket framing
    // -----------------------------------------------------------------

    @Test
    void roundTripsAGsiMessage() {
        byte[] message = GsiMessage.encode(GsiMessage.STEP_CLIENT_CERT, List.of(
                GsiMessage.Bucket.of(GsiMessage.BUCKET_CRYPTOMOD, "ssl"),
                GsiMessage.Bucket.of(GsiMessage.BUCKET_VERSION, 10400),
                new GsiMessage.Bucket(GsiMessage.BUCKET_MAIN, new byte[] {1, 2, 3, 4})));
        assertEquals("gsi", new String(message, 0, 3, StandardCharsets.US_ASCII));
        assertEquals(0, message[3], "the name is NUL-terminated");

        GsiMessage.Decoded decoded = GsiMessage.decode(message);
        assertEquals(GsiMessage.STEP_CLIENT_CERT, decoded.step());
        assertEquals(3, decoded.buckets().size());
        assertEquals("ssl", new String(decoded.find(GsiMessage.BUCKET_CRYPTOMOD),
                StandardCharsets.US_ASCII));
        assertArrayEquals(new byte[] {1, 2, 3, 4}, decoded.find(GsiMessage.BUCKET_MAIN));
        assertArrayEquals(new byte[] {0, 0, 0x28, (byte) 0xA0},
                decoded.find(GsiMessage.BUCKET_VERSION));
        assertNull(decoded.find(GsiMessage.BUCKET_RTAG), "a bucket that is not there");
        assertArrayEquals(new byte[] {1, 2, 3, 4},
                GsiMessage.find(message, GsiMessage.BUCKET_MAIN));
    }

    @Test
    void stopsAtTheClosingBucket() {
        byte[] message = GsiMessage.encode(GsiMessage.STEP_SERVER_INIT,
                List.of(GsiMessage.Bucket.of(GsiMessage.BUCKET_RTAG, "tag")));
        byte[] withTrailer = new byte[message.length + 8];
        System.arraycopy(message, 0, withTrailer, 0, message.length);
        assertEquals(1, GsiMessage.decode(withTrailer).buckets().size());
    }

    @Test
    void refusesAGsiMessageThatIsNotOne() {
        assertThrows(XrdAuthException.class, () -> GsiMessage.decode(new byte[0]));
        assertThrows(XrdAuthException.class,
                () -> GsiMessage.decode("gsi".getBytes(StandardCharsets.US_ASCII)));
        assertThrows(XrdAuthException.class, () -> GsiMessage.decode(
                new byte[] {'g', 's', 'i', 0, 0, 0, 0x07, (byte) 0xD0, 0, 0, 0x0B,
                        (byte) 0xB9, 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF}));
        assertNull(GsiMessage.find(new byte[0], GsiMessage.BUCKET_MAIN));
    }

    // -----------------------------------------------------------------

    /** A JWT with the given claims; the signature is never looked at. */
    private static String jwt(String claims) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString("{\"alg\":\"RS256\"}".getBytes(StandardCharsets.UTF_8))
                + "." + encoder.encodeToString(claims.getBytes(StandardCharsets.UTF_8))
                + ".c2lnbmF0dXJl";
    }
}

package io.github.robc.jroot.auth;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdAuthException;
import io.github.robc.jroot.crypto.Blowfish;
import io.github.robc.jroot.crypto.Signer;
import io.github.robc.jroot.wire.XrdConst;

/**
 * {@code sss}: the keytab, the credential it mints, and the {@code bf32}
 * those and {@code kXR_sigver} all run on.
 *
 * <p>The encodings are pinned against blobs produced by an independent
 * implementation of the same C format, so a mistake here shows up as a
 * mismatch rather than as a server quietly refusing to log in.
 */
class SssTest {

    private static final HexFormat HEX = HexFormat.of();

    /** Bytes 0x01..0x20: a 32-byte secret, the length xrdsssadmin writes. */
    private static final byte[] SECRET = secret();

    private static byte[] secret() {
        byte[] out = new byte[32];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) (i + 1);
        }
        return out;
    }

    private static byte[] nonce() {
        byte[] out = new byte[SssCredential.NONCE_LEN];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) i;
        }
        return out;
    }

    private static SssKeytab.Key key(long id) {
        return new SssKeytab.Key(id, SECRET, "", "", "", 0);
    }

    private static Path keytab(Path directory, String content) throws Exception {
        Path path = directory.resolve("sss.keytab");
        Files.writeString(path, content);
        Files.setPosixFilePermissions(path,
                java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        return path;
    }

    // -----------------------------------------------------------------
    // The cipher
    // -----------------------------------------------------------------

    @Test
    void encryptsTheBlowfishTestVector() {
        // A zero key, a zero IV and a zero block: CFB64 hands back the raw
        // block encryption, which is Blowfish's own published vector.
        byte[] out = new Blowfish(new byte[8]).encryptCfb64(new byte[8], new byte[8]);
        assertEquals("4ef997456198dd78", HEX.formatHex(out));
    }

    @Test
    void ridesOverBlockBoundariesAndBackAgain() {
        byte[] key = "TESTKEY".getBytes(StandardCharsets.US_ASCII);
        byte[] plain = "The quick brown fox".getBytes(StandardCharsets.US_ASCII);
        Blowfish blowfish = new Blowfish(key);
        byte[] cipher = blowfish.encryptCfb64(new byte[8], plain);
        assertEquals("45bb5224e6e3bd1bde31d91b5e9a8341f221e0", HEX.formatHex(cipher));
        assertEquals(plain.length, cipher.length, "CFB never changes the length");
        assertArrayEquals(plain, blowfish.decryptCfb64(new byte[8], cipher));
    }

    @Test
    void refusesAKeyBlowfishCannotTake() {
        assertThrows(XrdAuthException.class, () -> new Blowfish(new byte[3]));
        assertThrows(XrdAuthException.class, () -> new Blowfish(new byte[57]));
        assertThrows(XrdAuthException.class,
                () -> new Blowfish(SECRET).encryptCfb64(new byte[7], new byte[8]));
    }

    @Test
    void bf32AppendsACrcAndIsDeterministic() {
        byte[] plain = "signed".getBytes(StandardCharsets.US_ASCII);
        byte[] first = Blowfish.bf32(SECRET, plain);
        assertEquals(plain.length + 4, first.length);
        assertArrayEquals(first, Blowfish.bf32(SECRET, plain),
                "a zero IV is what lets a verifier re-encrypt rather than decrypt");

        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(plain);
        byte[] recovered = new Blowfish(SECRET).decryptCfb64(new byte[8], first);
        assertEquals(crc.getValue(),
                ByteBuffer.wrap(recovered, plain.length, 4).getInt() & 0xFFFFFFFFL);
    }

    // -----------------------------------------------------------------
    // The credential
    // -----------------------------------------------------------------

    @Test
    void mintsTheCredentialByteForByte() {
        byte[] blob = SssCredential.encode(key(7), "jane", nonce(), 0x01020304);
        assertEquals("7373730001000030" + "0000000000000007"
                + "07cd8cd16f18208a2061b873ca48eb8620239de6801a809b7c9c5c021fdc64a48"
                + "3d188ee58a097362d25aef32a9d24bf0116da4d",
                HEX.formatHex(blob));
    }

    @Test
    void putsTheKeyIdAndCipherInTheClearHeader() {
        byte[] blob = SssCredential.encode(key(0x0102030405060708L), "jane", nonce(), 0);
        assertEquals("sss", new String(blob, 0, 3, StandardCharsets.US_ASCII));
        assertEquals(0, blob[3]);
        assertEquals(1, blob[4], "protocol version");
        assertEquals(0, blob[6], "no named key: the id selects it");
        assertEquals('0', blob[7], "kXRS_bf32");
        assertEquals(0x0102030405060708L, ByteBuffer.wrap(blob, 8, 8).getLong());
    }

    @Test
    void carriesTheUserInsideTheEncryption() {
        byte[] blob = SssCredential.encode(key(1), "jane", nonce(), 0x01020304);
        byte[] body = new Blowfish(SECRET).decryptCfb64(new byte[8],
                java.util.Arrays.copyOfRange(blob, SssCredential.HEADER_LEN, blob.length));
        assertArrayEquals(nonce(), java.util.Arrays.copyOf(body, SssCredential.NONCE_LEN));
        assertEquals(0x01020304, ByteBuffer.wrap(body, SssCredential.NONCE_LEN, 4).getInt());
        assertEquals(SssCredential.OPT_USEDATA, body[SssCredential.DATA_HEADER_LEN - 1]);
        assertEquals(SssCredential.TYPE_NAME, body[SssCredential.DATA_HEADER_LEN]);
        assertEquals(5, body[SssCredential.DATA_HEADER_LEN + 2], "\"jane\" and its NUL");
        assertEquals("jane\0", new String(body, SssCredential.DATA_HEADER_LEN + 3, 5,
                StandardCharsets.UTF_8));
    }

    @Test
    void trimsAUserNameThatWouldOverrunTheField() {
        String long_ = "u".repeat(200);
        byte[] blob = SssCredential.encode(key(1), long_, nonce(), 0);
        byte[] body = new Blowfish(SECRET).decryptCfb64(new byte[8],
                java.util.Arrays.copyOfRange(blob, SssCredential.HEADER_LEN, blob.length));
        assertEquals(SssCredential.MAX_NAME, body[SssCredential.DATA_HEADER_LEN + 2]);
        assertEquals(0, body[body.length - 5], "still NUL-terminated");
    }

    @Test
    void freshCredentialsDifferAndAreDatedNow() {
        SssCredential credential = new SssCredential(key(1), "jane");
        byte[] first = credential.initial();
        byte[] second = credential.initial();
        assertNotEquals(HEX.formatHex(first), HEX.formatHex(second), "the nonce is fresh");

        byte[] body = new Blowfish(SECRET).decryptCfb64(new byte[8],
                java.util.Arrays.copyOfRange(first, SssCredential.HEADER_LEN, first.length));
        long generated = ByteBuffer.wrap(body, SssCredential.NONCE_LEN, 4).getInt();
        long expected = Instant.now().getEpochSecond() - SssCredential.BASE_TIME;
        assertTrue(Math.abs(expected - generated) < 60,
                "generated " + generated + " against " + expected);
    }

    @Test
    void refusesToMintFromAnExpiredKey() {
        SssKeytab.Key expired = new SssKeytab.Key(1, SECRET, "", "", "", 1000);
        XrdAuthException e = assertThrows(XrdAuthException.class,
                () -> new SssCredential(expired, "jane").initial());
        assertTrue(e.getMessage().contains("expired"), e.getMessage());
    }

    // -----------------------------------------------------------------
    // The keytab
    // -----------------------------------------------------------------

    @Test
    void readsTheFieldsXrdsssadminWrites(@TempDir Path directory) throws Exception {
        Path path = keytab(directory, """
                # a comment
                0 u:atlas g:atlas n:mykey N:3 c:1700000000 e:0 k:0102030405060708

                1 u:cms g:cms n:other N:4 e:0 k:aabb  # trailing comment
                """);
        List<SssKeytab.Key> keys = SssKeytab.read(path);
        assertEquals(2, keys.size());
        assertEquals(3, keys.get(0).id());
        assertEquals("mykey", keys.get(0).name());
        assertEquals("atlas", keys.get(0).user());
        assertArrayEquals(HEX.parseHex("0102030405060708"), keys.get(0).secret());
        assertArrayEquals(HEX.parseHex("aabb"), keys.get(1).secret());
    }

    @Test
    void dropsLinesThatAreNotKeys(@TempDir Path directory) throws Exception {
        Path path = keytab(directory, """
                2 u:x g:x N:1 k:aabb
                0 u:x g:x N:2
                0 u:x g:x N:3 k:zz
                0 u:x g:x N:4 k:aabbcc
                """);
        List<SssKeytab.Key> keys = SssKeytab.read(path);
        assertEquals(1, keys.size(), "an unknown version, no key and bad hex are all skipped");
        assertEquals(4, keys.get(0).id());
    }

    @Test
    void leavesExpiredKeysOutUnlessAskedForThem(@TempDir Path directory) throws Exception {
        Path path = keytab(directory, """
                0 u:x g:x N:1 e:1000 k:aabbccdd
                0 u:x g:x N:2 e:0 k:eeff0011
                """);
        assertEquals(List.of(2L), SssKeytab.read(path).stream()
                .map(SssKeytab.Key::id).toList());
        assertEquals(2, SssKeytab.read(path, true).size());
        assertTrue(SssKeytab.read(path, true).get(0).isExpired());
    }

    @Test
    void refusesAKeytabOthersCanRead(@TempDir Path directory) throws Exception {
        Path path = keytab(directory, "0 u:x g:x N:1 k:aabbccdd\n");
        Files.setPosixFilePermissions(path,
                java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--"));
        XrdAuthException e = assertThrows(XrdAuthException.class, () -> SssKeytab.read(path));
        assertTrue(e.getMessage().contains("0600"), e.getMessage());
    }

    @Test
    void keepsTheSecretOutOfEveryPrintedForm(@TempDir Path directory) throws Exception {
        Path path = keytab(directory, "0 u:x g:x n:mykey N:1 k:0102030405060708\n");
        SssKeytab.Key key = SssKeytab.read(path).get(0);
        assertFalse(key.toString().contains("0102030405060708"));
        assertFalse(new SssCredential(key, "jane").toString().contains("0102030405060708"));
        assertTrue(key.toString().contains("redacted"));
    }

    // -----------------------------------------------------------------
    // Selection and signing
    // -----------------------------------------------------------------

    @Test
    void takesTheKeyTheServerNamesOrNoneAtAll(@TempDir Path directory) throws Exception {
        Path path = keytab(directory, """
                0 u:x g:x n:first N:1 k:0102030405060708
                0 u:x g:x n:second N:2 k:1112131415161718
                """);
        Config config = Config.defaults().withKeytab(path).withUsername("jane");

        assertEquals(1, SssCredential.available(new SecurityOffer("sss", ""), config)
                .orElseThrow().key().id(), "no name asked for: the first key");
        assertEquals(2, SssCredential.available(new SecurityOffer("sss", "n:second"), config)
                .orElseThrow().key().id());
        assertThrows(XrdAuthException.class, () ->
                SssCredential.available(new SecurityOffer("sss", "n:absent"), config));
    }

    @Test
    void offersNothingWhenThereIsNoKeytab(@TempDir Path directory) {
        Config config = Config.defaults().withKeytab(directory.resolve("absent"));
        assertEquals(Optional.empty(),
                SssCredential.available(new SecurityOffer("sss", ""), config));
    }

    @Test
    void appearsInTheLadderAndExplainsItselfWhenItCannot(@TempDir Path directory)
            throws Exception {
        Path path = keytab(directory, "0 u:x g:x N:1 k:0102030405060708\n");
        List<SecurityOffer> offers = SecurityOffer.parse("&P=sss&P=unix");
        Config config = Config.defaults().withKeytab(path);
        CredentialLadder ladder = CredentialLadder.build(offers, config);
        assertEquals("sss", ladder.candidates().get(0).credential().name());

        CredentialLadder without = CredentialLadder.build(offers,
                Config.defaults().withKeytab(directory.resolve("absent")));
        assertTrue(without.explain().contains("no shared-secret keytab"), without.explain());
    }

    @Test
    void signsRequestsWithTheSharedSecretRatherThanAes() {
        SssCredential credential = new SssCredential(key(1), "jane");
        assertEquals(Signer.Cipher.BF32, credential.sessionCipher());
        assertArrayEquals(SECRET, credential.sessionKey());

        byte[] frame = new byte[XrdConst.REQUEST_HDRLEN];
        frame[2] = (byte) (XrdConst.kXR_rm >> 8);
        frame[3] = (byte) XrdConst.kXR_rm;
        Signer signer = new Signer(credential.sessionKey(), Signer.Cipher.BF32,
                XrdConst.kXR_secStandard, Map.of(), false, false);
        Signer.Signature signature = signer.sign(frame);

        byte[] expected = Blowfish.bf32(SECRET,
                Signer.hash(1, frame, new byte[0], false));
        assertArrayEquals(expected, signature.bytes());
        assertEquals(36, signature.bytes().length, "a SHA-256 digest and its CRC");
    }
}

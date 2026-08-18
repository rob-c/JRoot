package io.github.robc.jroot;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import io.github.robc.jroot.http.MockHttpStorage;
import io.github.robc.jroot.http.MockTapeServer;
import io.github.robc.jroot.wire.Types.DirEntry;
import io.github.robc.jroot.wire.Types.PrepareStatus;
import io.github.robc.jroot.wire.Types.ReadVSegment;
import io.github.robc.jroot.wire.Types.StatInfo;
import io.github.robc.jroot.wire.XrdConst;

/**
 * The facade: which transport a URL picks, what the local one does, and what
 * happens where two of them meet.
 */
@Timeout(30)
class JRootTest {

    private static final byte[] CONTENT =
            "the quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);

    @TempDir
    Path dir;

    private JRoot jroot;

    @BeforeEach
    void open() {
        jroot = JRoot.open();
    }

    @AfterEach
    void close() {
        jroot.close();
    }

    // -----------------------------------------------------------------
    // Dispatch
    // -----------------------------------------------------------------

    @Test
    void picksTheTransportFromTheScheme() {
        assertEquals(JRoot.Transport.XROOTD, JRoot.transportOf("root://door//store/f"));
        assertEquals(JRoot.Transport.XROOTD, JRoot.transportOf("xroots://door//store/f"));
        assertEquals(JRoot.Transport.HTTP, JRoot.transportOf("https://door/store/f"));
        assertEquals(JRoot.Transport.HTTP, JRoot.transportOf("davs://door/store/f"));
        assertEquals(JRoot.Transport.LOCAL, JRoot.transportOf("file:///store/f"));
        assertEquals(JRoot.Transport.LOCAL, JRoot.transportOf("/store/f"));
        assertEquals(JRoot.Transport.LOCAL, JRoot.transportOf("relative/f"));
    }

    @Test
    void refusesASchemeItCannotSpeak() {
        XrdException failure =
                assertThrows(XrdException.class, () -> JRoot.transportOf("gsiftp://door/f"));
        assertTrue(failure.getMessage().contains("gsiftp"));
    }

    @Test
    void takesAPathWithAColonInItForAPath() {
        // A name may hold a colon; a scheme may not hold a slash before one.
        assertEquals(JRoot.Transport.LOCAL, JRoot.transportOf("/data/run:1/f"));
        assertEquals(Path.of("/data/run:1/f"), JRoot.localPath("/data/run:1/f"));
    }

    @Test
    void readsAFileUrlBackToAPath() {
        assertEquals(Path.of("/store/data/f"), JRoot.localPath("file:///store/data/f"));
        assertEquals(Path.of("/store/data/f"), JRoot.localPath("/store/data/f"));
        // file://host/path with a relative authority is how a URI spells a
        // relative path; keep the authority as the first component.
        assertEquals(Path.of("data/f"), JRoot.localPath("file://data/f"));
    }

    @Test
    void handsBackTheSameClientEveryTime() {
        assertTrue(jroot.xrootd() == jroot.xrootd());
        assertTrue(jroot.webdav() == jroot.webdav());
        assertTrue(jroot.http() == jroot.webdav(), "HTTP is the WebDAV client without the verbs");
    }

    // -----------------------------------------------------------------
    // Local filesystem
    // -----------------------------------------------------------------

    @Test
    void statsALocalFile() throws IOException {
        Path file = dir.resolve("f.root");
        Files.write(file, CONTENT);
        StatInfo stat = jroot.stat(file.toString());
        assertEquals(CONTENT.length, stat.size());
        assertFalse(stat.isDirectory());
        assertEquals(file.toString(), stat.path());
        assertTrue(jroot.stat(dir.toString()).isDirectory());
        assertTrue(jroot.exists(file.toString()));
        assertFalse(jroot.exists(dir.resolve("nothing").toString()));
    }

    @Test
    void reportsAMissingLocalFileAsTheProtocolWould() {
        String missing = dir.resolve("nothing").toString();
        XrdServerException failure =
                assertThrows(XrdServerException.class, () -> jroot.stat(missing));
        assertEquals(XrdConst.kXR_NotFound, failure.code());
        assertTrue(failure.isNotFound());
        assertTrue(jroot.statIfPresent(missing).isEmpty());
        assertTrue(jroot.statIfPresent(dir.toString()).isPresent());
    }

    @Test
    void listsALocalDirectoryInOrder() throws IOException {
        Files.write(dir.resolve("b"), CONTENT);
        Files.write(dir.resolve("a"), new byte[3]);
        Files.createDirectory(dir.resolve("c"));
        List<DirEntry> entries = jroot.list(dir.toString());
        assertEquals(List.of("a", "b", "c"), entries.stream().map(DirEntry::name).toList());
        assertEquals(3, entries.get(0).stat().orElseThrow().size());
        assertTrue(entries.get(2).isDirectory());
    }

    @Test
    void readsALocalFileWholeAndInPieces() throws IOException {
        Path file = dir.resolve("f.root");
        Files.write(file, CONTENT);
        assertArrayEquals(CONTENT, jroot.read(file.toString()));
        assertEquals("quick", new String(jroot.read(file.toString(), 4, 5),
                StandardCharsets.UTF_8));
        assertEquals("dog", new String(
                jroot.read(file.toString(), CONTENT.length - 3, 100), StandardCharsets.UTF_8),
                "a read past the end stops at the end");

        List<ReadVSegment> segments = jroot.readV(file.toString(),
                List.of(new long[] {4, 5}, new long[] {10, 5}));
        assertEquals(2, segments.size());
        assertEquals(10, segments.get(1).offset());
        assertEquals("brown", new String(segments.get(1).data(), StandardCharsets.UTF_8));
    }

    @Test
    void writesALocalFileAndTheDirectoriesAboveIt() {
        Path file = dir.resolve("new/deeper/f.root");
        jroot.write(file.toString(), CONTENT);
        assertArrayEquals(CONTENT, jroot.read(file.toString()));
    }

    @Test
    void streamsALocalFileInChunks() throws IOException {
        Path file = dir.resolve("f.root");
        Files.write(file, CONTENT);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertEquals(CONTENT.length, jroot.stream(file.toString(), out));
        assertArrayEquals(CONTENT, out.toByteArray());
    }

    @Test
    void makesAndRemovesLocalDirectories() {
        Path child = dir.resolve("a");
        jroot.mkdir(child.toString());
        assertTrue(Files.isDirectory(child));

        XrdServerException exists =
                assertThrows(XrdServerException.class, () -> jroot.mkdir(child.toString()));
        assertEquals(XrdConst.kXR_ItExists, exists.code());

        Path deep = dir.resolve("x/y/z");
        assertThrows(XrdException.class, () -> jroot.mkdir(deep.toString()));
        jroot.mkdir(deep.toString(), true);
        assertTrue(Files.isDirectory(deep));

        jroot.write(deep.resolve("f").toString(), CONTENT);
        jroot.rmdir(dir.resolve("x").toString());
        assertFalse(Files.exists(dir.resolve("x")), "rmdir takes the whole tree");
    }

    @Test
    void removesALocalFile() throws IOException {
        Path file = dir.resolve("f.root");
        Files.write(file, CONTENT);
        jroot.rm(file.toString());
        assertFalse(Files.exists(file));
        XrdServerException failure =
                assertThrows(XrdServerException.class, () -> jroot.rm(file.toString()));
        assertEquals(XrdConst.kXR_NotFound, failure.code());
    }

    @Test
    void reportsAPermissionDeniedAsTheProtocolWould() throws IOException {
        Path file = dir.resolve("secret.root");
        Files.write(file, CONTENT);
        Files.setPosixFilePermissions(file, java.util.Set.of());
        org.junit.jupiter.api.Assumptions.assumeTrue(!Files.isReadable(file),
                "this user is not bound by file modes");

        XrdServerException failure = assertThrows(XrdServerException.class,
                () -> jroot.read(file.toString()));
        assertEquals(XrdConst.kXR_NotAuthorized, failure.code());
        assertTrue(failure.getMessage().contains("not permitted to read"));
    }

    @Test
    void renamesWithinTheLocalFilesystem() throws IOException {
        Path from = dir.resolve("from.root");
        Path to = dir.resolve("to.root");
        Files.write(from, CONTENT);
        jroot.mv(from.toString(), to.toString());
        assertFalse(Files.exists(from));
        assertArrayEquals(CONTENT, Files.readAllBytes(to));
    }

    @Test
    void refusesToRenameAcrossTransports() {
        XrdException failure = assertThrows(XrdException.class,
                () -> jroot.mv("root://door//store/f", dir.resolve("f").toString()));
        assertTrue(failure.getMessage().contains("across transports"));
        assertTrue(failure.getMessage().contains("copy then remove"));
    }

    @Test
    void hasNoLocalChecksumToOffer() throws IOException {
        Path file = dir.resolve("f.root");
        Files.write(file, CONTENT);
        assertTrue(jroot.checksum(file.toString()).isEmpty());
    }

    @Test
    void copiesLocallyInChunks() throws IOException {
        Path from = dir.resolve("from.root");
        Path to = dir.resolve("sub/to.root");
        byte[] large = new byte[3 * 1024 * 1024];
        new java.util.Random(7).nextBytes(large);
        Files.write(from, large);
        jroot.copy(from.toString(), to.toString());
        assertArrayEquals(large, Files.readAllBytes(to));
    }

    @Test
    void changesTheModeOfALocalFile() throws IOException {
        Path file = dir.resolve("f.root");
        Files.write(file, CONTENT);
        jroot.chmod(file.toString(), 0640);
        assertEquals(PosixFilePermissions.fromString("rw-r-----"),
                Files.getPosixFilePermissions(file));
        jroot.chmod(file.toString(), 0755);
        assertEquals(PosixFilePermissions.fromString("rwxr-xr-x"),
                Files.getPosixFilePermissions(file));
    }

    @Test
    void truncatesALocalFileInEitherDirection() throws IOException {
        Path file = dir.resolve("f.root");
        Files.write(file, CONTENT);
        jroot.truncate(file.toString(), 9);
        assertEquals("the quick", Files.readString(file));

        // Past the end is a hole, not an error: the file grows and the gap
        // reads back as zeroes.
        jroot.truncate(file.toString(), 16);
        assertEquals(16, Files.size(file));
        assertArrayEquals(new byte[7],
                java.util.Arrays.copyOfRange(Files.readAllBytes(file), 9, 16));
    }

    @Test
    void carriesExtendedAttributesOnALocalFile() throws IOException {
        Path file = dir.resolve("f.root");
        Files.write(file, CONTENT);
        org.junit.jupiter.api.Assumptions.assumeTrue(
                Files.getFileAttributeView(file, UserDefinedFileAttributeView.class) != null,
                "this filesystem has no extended attributes");

        byte[] checksum = "adler32:1234".getBytes(StandardCharsets.UTF_8);
        jroot.setAttribute(file.toString(), "user.checksum", checksum);
        jroot.setAttribute(file.toString(), "user.run", "1".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(checksum,
                jroot.attribute(file.toString(), "user.checksum").orElseThrow());
        assertEquals(java.util.Set.of("user.checksum", "user.run"),
                jroot.attributes(file.toString()).keySet());

        jroot.deleteAttribute(file.toString(), "user.run");
        assertEquals(java.util.Set.of("user.checksum"),
                jroot.attributes(file.toString()).keySet());
        assertTrue(jroot.attribute(file.toString(), "user.run").isEmpty());
    }

    @Test
    void copiesALocalTreeContentsFirst() throws IOException {
        Path source = dir.resolve("run1");
        Files.createDirectories(source.resolve("sub"));
        Files.write(source.resolve("a.root"), CONTENT);
        Files.write(source.resolve("sub/b.root"), CONTENT);

        Path target = dir.resolve("copy");
        jroot.copyTree(source.toString(), target.toString());
        assertArrayEquals(CONTENT, Files.readAllBytes(target.resolve("a.root")));
        assertArrayEquals(CONTENT, Files.readAllBytes(target.resolve("sub/b.root")));
        assertFalse(Files.exists(target.resolve("run1")), "the source's contents, not the source");
    }

    @Test
    void removesALocalTreeAndAPlainFileAlike() throws IOException {
        Path tree = dir.resolve("run1");
        Files.createDirectories(tree.resolve("sub"));
        Files.write(tree.resolve("sub/b.root"), CONTENT);
        jroot.rmTree(tree.toString());
        assertFalse(Files.exists(tree));

        Path file = dir.resolve("f.root");
        Files.write(file, CONTENT);
        jroot.rmTree(file.toString());
        assertFalse(Files.exists(file));
    }

    @Test
    void saysWhichOfTheseHttpHasNoWordFor() {
        String url = "https://door/store/f.root";
        assertTrue(assertThrows(XrdException.class, () -> jroot.chmod(url, 0644))
                .getMessage().contains("no permission bits"));
        assertTrue(assertThrows(XrdException.class, () -> jroot.truncate(url, 0))
                .getMessage().contains("not truncate"));
        assertTrue(assertThrows(XrdException.class, () -> jroot.attributes(url))
                .getMessage().contains("extended attributes"));
        assertThrows(XrdException.class, () -> jroot.attribute(url, "user.checksum"));
        assertThrows(XrdException.class,
                () -> jroot.setAttribute(url, "user.checksum", CONTENT));
        assertThrows(XrdException.class, () -> jroot.deleteAttribute(url, "user.checksum"));
    }

    // -----------------------------------------------------------------
    // Where two transports meet
    // -----------------------------------------------------------------

    @Test
    void downloadsFromHttpToALocalFile() throws Exception {
        try (MockHttpStorage server = new MockHttpStorage()) {
            server.put("/store/f.root", CONTENT);
            Path target = dir.resolve("f.root");
            jroot.readTo(server.url("/store/f.root"), target);
            assertArrayEquals(CONTENT, Files.readAllBytes(target));
        }
    }

    @Test
    void uploadsALocalFileOverHttp() throws Exception {
        try (MockHttpStorage server = new MockHttpStorage()) {
            Path source = dir.resolve("f.root");
            Files.write(source, CONTENT);
            jroot.writeFrom(source, server.url("/store/f.root"));
            assertArrayEquals(CONTENT, server.contentOf("/store/f.root"));
        }
    }

    @Test
    void stagesACopyThatEndsAtAnHttpDestination() throws Exception {
        try (MockHttpStorage server = new MockHttpStorage()) {
            server.put("/store/from.root", CONTENT);
            jroot.copy(server.url("/store/from.root"), server.url("/store/to.root"));
            assertArrayEquals(CONTENT, server.contentOf("/store/to.root"));
        }
    }

    @Test
    void refusesAThirdPartyCopyBetweenTwoDifferentProtocols() {
        // The two arrangements share nothing, so there is no copy to make
        // between them - only an ordinary one through this process.
        XrdException failure = assertThrows(XrdException.class,
                () -> jroot.thirdPartyCopy("root://door//store/f", "https://other/store/f"));
        assertTrue(failure.getMessage().contains("two servers of the same"),
                failure.getMessage());
        assertThrows(XrdException.class,
                () -> jroot.thirdPartyCopy("https://door/store/f", dir.resolve("f").toString()));
        assertThrows(XrdException.class,
                () -> jroot.thirdPartyCopy(dir.resolve("a").toString(), dir.resolve("b").toString()));
    }

    // -----------------------------------------------------------------
    // Staging
    // -----------------------------------------------------------------

    @Test
    void treatsALocalFileAsAlreadyStaged() throws IOException {
        Path file = Files.write(dir.resolve("staged.root"), CONTENT);
        assertEquals("", jroot.stage(List.of(file.toString())));
        assertEquals("", jroot.stage(List.of(file.toString()), "P1D"));
        List<PrepareStatus> statuses =
                jroot.stageStatus("", List.of(file.toString(), dir.resolve("no").toString()));
        assertTrue(statuses.get(0).online());
        assertTrue(statuses.get(0).exists());
        assertFalse(statuses.get(1).exists());
        assertFalse(statuses.get(1).online());
        jroot.cancelStage("", List.of(file.toString()));
    }

    @Test
    void reportsALocalFileAsOnlineAndNothingAtAllAsMissing() throws IOException {
        Path file = Files.write(dir.resolve("here.root"), CONTENT);
        List<PrepareStatus> where =
                jroot.locality(List.of(file.toString(), dir.resolve("gone").toString()));
        assertEquals("ONLINE", where.get(0).state());
        assertFalse(where.get(0).onTape());
        assertEquals("no such file", where.get(1).error());
    }

    @Test
    void hasNothingToDoWithAnEmptyListOfFiles() {
        assertEquals("", jroot.stage(List.of()));
        assertTrue(jroot.stageStatus("h", List.of()).isEmpty());
        assertTrue(jroot.locality(List.of()).isEmpty());
        jroot.cancelStage("h", List.of());
    }

    @Test
    void asksTheServerWhetherAFileIsStillOnTape() throws IOException {
        try (MockTapeServer server = new MockTapeServer()) {
            server.answering("/api/v1/tape/archiveinfo", 200,
                    "[{\"path\":\"/store/cold.root\",\"locality\":\"NEARLINE\"}]");
            List<PrepareStatus> where = jroot.locality(List.of(server.url("/store/cold.root")));
            assertTrue(where.get(0).onTape());
            assertFalse(where.get(0).online());
        }
    }

    @Test
    void saysWhatItIs() {
        assertTrue(jroot.toString().startsWith("JRoot["));
        assertTrue(JRoot.open(Config.defaults()).config() != null);
    }
}

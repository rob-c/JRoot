package io.github.robc.jroot.transfer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import io.github.robc.jroot.JRoot;
import io.github.robc.jroot.XrdException;
import io.github.robc.jroot.client.XrdUrl;
import io.github.robc.jroot.http.MockHttpStorage;
import io.github.robc.jroot.wire.Types.LocationInfo;
import io.github.robc.jroot.wire.XrdConst;

/**
 * The copy engine: chunks drawn from whichever replica answers, written
 * where they belong, and checked against what the source says they should
 * have come to.
 */
@Timeout(60)
class TransferTest {

    @TempDir
    Path dir;

    private JRoot jroot;
    private Transfer transfer;
    private byte[] content;
    private Path file;

    @BeforeEach
    void open() throws IOException {
        jroot = JRoot.open();
        transfer = jroot.transfer();
        content = new byte[1 << 18];
        new Random(20260818).nextBytes(content);
        file = dir.resolve("source.root");
        Files.write(file, content);
    }

    @AfterEach
    void close() {
        jroot.close();
    }

    // -----------------------------------------------------------------
    // Moving the bytes
    // -----------------------------------------------------------------

    @Test
    void copiesAFileAndSaysWhatItCheckedItAgainst() throws IOException {
        Path target = dir.resolve("copy.root");
        Transfer.Result result = transfer.copy(file.toString(), target.toString());

        assertArrayEquals(content, Files.readAllBytes(target));
        assertEquals(content.length, result.bytes());
        assertEquals(List.of(file.toString()), result.sources());
        assertEquals("adler32", result.algorithm());
        assertEquals(Checksum.of("adler32", file), result.checksum());
        assertTrue(result.verified());
        assertTrue(result.toString().contains("adler32 verified"), result.toString());
    }

    @Test
    void copiesAnEmptyFileToAnEmptyFile() throws IOException {
        Path empty = Files.write(dir.resolve("empty.root"), new byte[0]);
        Path target = dir.resolve("empty-copy.root");
        Transfer.Result result = transfer.copy(empty.toString(), target.toString());

        assertEquals(0, result.bytes());
        assertTrue(Files.exists(target));
        assertEquals(0, Files.size(target));
        assertTrue(result.verified());
    }

    @Test
    void dividesTheFileBetweenSeveralWorkers() throws IOException {
        Path target = dir.resolve("parallel.root");
        Transfer.Result result = transfer.run(Transfer.Plan.of(file.toString(), target.toString())
                .withChunkSize(4096)
                .withParallel(8));

        assertArrayEquals(content, Files.readAllBytes(target));
        assertEquals(content.length, result.bytes());
        assertTrue(result.verified());
    }

    @Test
    void drawsFromEveryReplicaItWasGiven() throws IOException {
        Path second = Files.write(dir.resolve("replica-2.root"), content);
        Path third = Files.write(dir.resolve("replica-3.root"), content);
        Path target = dir.resolve("replicated.root");
        Transfer.Result result = transfer.run(Transfer.Plan.of(
                        List.of(file.toString(), second.toString(), third.toString()),
                        target.toString())
                .withChunkSize(8192)
                .withParallel(3));

        assertArrayEquals(content, Files.readAllBytes(target));
        assertEquals(3, result.sources().size());
        assertTrue(result.verified());
    }

    @Test
    void stepsPastAReplicaThatWillNotOpen() throws IOException {
        Path target = dir.resolve("failover.root");
        Transfer.Result result = transfer.run(Transfer.Plan.of(
                        List.of(dir.resolve("gone.root").toString(),
                                dir.resolve("also-gone.root").toString(),
                                file.toString()),
                        target.toString())
                .withChunkSize(16384)
                .withParallel(2));

        assertArrayEquals(content, Files.readAllBytes(target));
        assertTrue(result.verified());
    }

    @Test
    void givesUpWhenNoReplicaOpensAtAll() {
        XrdException failure = assertThrows(XrdException.class,
                () -> transfer.copy(dir.resolve("gone.root").toString(),
                        dir.resolve("nothing.root").toString()));
        assertTrue(failure.getMessage().contains("gone.root"), failure.getMessage());
    }

    @Test
    void refusesAPlanWithNothingToCopy() {
        assertThrows(XrdException.class,
                () -> transfer.run(Transfer.Plan.of(List.of(), dir.resolve("x").toString())));
    }

    @Test
    void reportsHowFarItHasGot() {
        AtomicLong last = new AtomicLong();
        List<Long> totals = java.util.Collections.synchronizedList(new ArrayList<>());
        Transfer.Result result = transfer.run(
                Transfer.Plan.of(file.toString(), dir.resolve("watched.root").toString())
                        .withChunkSize(4096)
                        .withParallel(4)
                        .withProgress((done, total) -> {
                            last.set(done);
                            totals.add(total);
                        }));

        assertEquals(content.length, last.get());
        assertEquals(content.length, result.bytes());
        assertFalse(totals.isEmpty());
        assertTrue(totals.stream().allMatch(total -> total == content.length),
                "the size was reported inconsistently: " + totals);
    }

    // -----------------------------------------------------------------
    // Checking it arrived
    // -----------------------------------------------------------------

    @Test
    void refusesACopyThatDoesNotMatchThePublishedChecksum() {
        Path target = dir.resolve("wrong.root");
        XrdException failure = assertThrows(XrdException.class,
                () -> transfer.run(Transfer.Plan.of(file.toString(), target.toString())
                        .withExpected("deadbeef")));
        assertTrue(failure.getMessage().contains("deadbeef"), failure.getMessage());
        assertTrue(failure.getMessage().contains("not the file"), failure.getMessage());
    }

    @Test
    void acceptsACopyThatMatchesThePublishedChecksum() {
        Transfer.Result result = transfer.run(
                Transfer.Plan.of(file.toString(), dir.resolve("right.root").toString())
                        .withExpected(Checksum.of("adler32", file)));
        assertTrue(result.verified());
    }

    @Test
    void checksWhicheverAlgorithmItWasAsked() {
        Transfer.Result result = transfer.run(
                Transfer.Plan.of(file.toString(), dir.resolve("sha.root").toString())
                        .withAlgorithm("SHA-256"));
        assertEquals("sha256", result.algorithm());
        assertEquals(Checksum.of("sha256", file), result.checksum());
        assertTrue(result.verified());
    }

    @Test
    void skipsTheCheckWhenToldTo() throws IOException {
        Path target = dir.resolve("unchecked.root");
        Transfer.Result result = transfer.run(
                Transfer.Plan.of(file.toString(), target.toString()).withVerify(false));

        assertArrayEquals(content, Files.readAllBytes(target));
        assertFalse(result.verified());
        assertEquals("", result.checksum());
        assertFalse(result.toString().contains("verified"), result.toString());
    }

    // -----------------------------------------------------------------
    // Where the sources come from
    // -----------------------------------------------------------------

    @Test
    void unfoldsAMetalinkIntoItsReplicas() throws IOException {
        Path metalink = Files.writeString(dir.resolve("bundle.meta4"), """
                <?xml version="1.0" encoding="UTF-8"?>
                <metalink xmlns="urn:ietf:params:xml:ns:metalink">
                  <file name="source.root">
                    <size>%d</size>
                    <hash type="adler32">%s</hash>
                    <url priority="2">%s</url>
                    <url priority="1">%s</url>
                  </file>
                </metalink>
                """.formatted(content.length, Checksum.of("adler32", file),
                dir.resolve("gone.root").toUri(), file.toUri()));

        Transfer.Plan resolved = transfer.resolve(
                Transfer.Plan.of(metalink.toString(), dir.resolve("from-meta.root").toString()));
        assertEquals(List.of(file.toUri().toString(), dir.resolve("gone.root").toUri().toString()),
                resolved.sources());
        assertEquals("adler32", resolved.algorithm());
        assertEquals(Checksum.of("adler32", file), resolved.expected());

        Transfer.Result result = transfer.run(resolved);
        assertArrayEquals(content, Files.readAllBytes(dir.resolve("from-meta.root")));
        assertTrue(result.verified());
    }

    @Test
    void refusesACopyTheMetalinkSaysIsADifferentFile() throws IOException {
        Path metalink = Files.writeString(dir.resolve("wrong.meta4"), """
                <?xml version="1.0" encoding="UTF-8"?>
                <metalink xmlns="urn:ietf:params:xml:ns:metalink">
                  <file name="source.root">
                    <hash type="adler32">01020304</hash>
                    <url>%s</url>
                  </file>
                </metalink>
                """.formatted(file.toUri()));

        XrdException failure = assertThrows(XrdException.class,
                () -> transfer.copy(metalink.toString(), dir.resolve("no.root").toString()));
        assertTrue(failure.getMessage().contains("01020304"), failure.getMessage());
    }

    @Test
    void willNotCopyAMetalinkThatNamesSeveralFiles() throws IOException {
        Path metalink = Files.writeString(dir.resolve("many.meta4"), """
                <?xml version="1.0" encoding="UTF-8"?>
                <metalink xmlns="urn:ietf:params:xml:ns:metalink">
                  <file name="a.root"><url>file:///a</url></file>
                  <file name="b.root"><url>file:///b</url></file>
                </metalink>
                """);

        XrdException failure = assertThrows(XrdException.class,
                () -> transfer.copy(metalink.toString(), dir.resolve("no.root").toString()));
        assertTrue(failure.getMessage().contains("2 files"), failure.getMessage());
    }

    @Test
    void leavesSourcesItWasGivenExplicitlyAlone() {
        List<String> sources = List.of("root://a//store/f", "root://b//store/f");
        assertEquals(sources,
                transfer.resolve(Transfer.Plan.of(sources, "/tmp/f")).sources());
        assertEquals(List.of("https://door/store/f"),
                transfer.resolve(Transfer.Plan.of("https://door/store/f", "/tmp/f")).sources());
    }

    @Test
    void readsTheAddressAServerWasLocatedAt() {
        XrdUrl url = XrdUrl.parse("root://redirector:1094//store/f?authz=abc");

        assertEquals("root://data.example:2094//store/f?authz=abc",
                Transfer.at(url, location("data.example:2094")).toString());

        XrdUrl six = Transfer.at(url, location("[2001:db8::1]:2094"));
        assertEquals("2001:db8::1", six.host());
        assertEquals(2094, six.port());

        // No port, and a port that is not a number, both fall back to 1094.
        assertEquals(XrdConst.DEFAULT_PORT, Transfer.at(url, location("data.example")).port());
        assertEquals("data.example", Transfer.at(url, location("data.example")).host());
        assertEquals(XrdConst.DEFAULT_PORT,
                Transfer.at(url, location("data.example:not-a-port")).port());
    }

    @Test
    void takesOnlyTheDataServersOutOfALocateAnswer() {
        assertFalse(new LocationInfo("manager:1094", 'M', 'r').isServer());
        assertTrue(new LocationInfo("data:1094", 'S', 'w').isServer());
    }

    private static LocationInfo location(String address) {
        return new LocationInfo(address, 'S', 'r');
    }

    // -----------------------------------------------------------------
    // A member of an archive
    // -----------------------------------------------------------------

    @Test
    void copiesOneMemberOutOfAnArchiveAndChecksItsOwnCrc() throws IOException {
        Path archive = dir.resolve("bundle.zip");
        try (java.util.zip.ZipOutputStream zip = new java.util.zip.ZipOutputStream(
                Files.newOutputStream(archive))) {
            zip.putNextEntry(new java.util.zip.ZipEntry("data/histograms.root"));
            zip.write(content);
            zip.closeEntry();
        }
        String source = archive + "?xrdcl.unzip=data/histograms.root";
        Path target = dir.resolve("member.root");

        Transfer.Plan resolved = transfer.resolve(Transfer.Plan.of(source, target.toString()));
        assertEquals("crc32", resolved.algorithm());
        assertEquals(Checksum.of("crc32", file), resolved.expected());

        Transfer.Result result = transfer.run(
                Transfer.Plan.of(source, target.toString()).withChunkSize(8192).withParallel(4));
        assertArrayEquals(content, Files.readAllBytes(target));
        assertEquals(content.length, result.bytes());
        assertEquals("crc32", result.algorithm());
        assertTrue(result.verified());
    }

    @Test
    void willNotCheckAMemberAgainstTheWholeArchive() {
        assertEquals("", transfer.checksumOf(file + "?xrdcl.unzip=m.root", "adler32"));
        assertFalse(transfer.checksumOf(file.toString(), "adler32").isEmpty());
    }

    // -----------------------------------------------------------------
    // An HTTP destination
    // -----------------------------------------------------------------

    @Test
    void stagesACopyThroughDiskWhenTheDestinationIsHttp() throws IOException {
        try (MockHttpStorage storage = new MockHttpStorage()) {
            Transfer.Result result = transfer.run(
                    Transfer.Plan.of(file.toString(), storage.url("/store/uploaded.root"))
                            .withChunkSize(8192)
                            .withParallel(4));

            assertArrayEquals(content, storage.contentOf("/store/uploaded.root"));
            assertEquals(content.length, result.bytes());
            assertTrue(storage.log().stream().anyMatch(line -> line.startsWith("PUT ")),
                    storage.log().toString());
        }
    }

    @Test
    void copiesOutOfHttpStorageAsWell() throws IOException {
        try (MockHttpStorage storage = new MockHttpStorage()) {
            storage.put("/store/remote.root", content);
            Path target = dir.resolve("pulled.root");
            Transfer.Result result = transfer.run(
                    Transfer.Plan.of(storage.url("/store/remote.root"), target.toString())
                            .withChunkSize(16384)
                            .withParallel(3));

            assertArrayEquals(content, Files.readAllBytes(target));
            assertEquals(content.length, result.bytes());
        }
    }

    // -----------------------------------------------------------------
    // Tuning
    // -----------------------------------------------------------------

    @Test
    void takesItsDefaultsFromTheEnvironmentButItsPlanFromTheCaller() {
        Transfer.Plan plain = Transfer.Plan.of("root://door//store/f", "/tmp/f");
        assertEquals(Transfer.DEFAULT_CHUNK, plain.chunkSize());
        assertEquals(Transfer.DEFAULT_PARALLEL, plain.parallel());
        assertEquals(Transfer.DEFAULT_RETRIES, plain.retries());

        Transfer.Plan tuned = Transfer.plan(List.of("root://door//store/f"), "/tmp/f");
        assertTrue(tuned.chunkSize() > 0);
        assertTrue(tuned.parallel() > 0);
        assertEquals("adler32", tuned.algorithm());
    }

    @Test
    void saysWhichClientItBelongsTo() {
        assertTrue(transfer.toString().startsWith("Transfer["), transfer.toString());
    }
}

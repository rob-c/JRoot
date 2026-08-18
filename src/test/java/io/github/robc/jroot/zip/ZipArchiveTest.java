package io.github.robc.jroot.zip;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.jupiter.api.Test;

import io.github.robc.jroot.XrdException;
import io.github.robc.jroot.transfer.Source;

/**
 * Reading a member out of a remote archive. The archives here are built by
 * the JDK's own writer, so what is being tested is that this reader agrees
 * with a real one rather than with itself.
 */
class ZipArchiveTest {

    private static final byte[] DEFLATABLE =
            "ROOT file contents, repeated. ".repeat(400).getBytes(StandardCharsets.UTF_8);
    private static final byte[] SMALL = "a histogram".getBytes(StandardCharsets.UTF_8);

    /** An archive of two members, one deflated and one stored verbatim. */
    private static byte[] archive() throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            zip.setMethod(ZipOutputStream.DEFLATED);
            zip.putNextEntry(new ZipEntry("data/big.root"));
            zip.write(DEFLATABLE);
            zip.closeEntry();
            ZipEntry stored = new ZipEntry("data/small.root");
            stored.setMethod(ZipEntry.STORED);
            stored.setSize(SMALL.length);
            stored.setCompressedSize(SMALL.length);
            CRC32 crc = new CRC32();
            crc.update(SMALL);
            stored.setCrc(crc.getValue());
            zip.putNextEntry(stored);
            zip.write(SMALL);
            zip.closeEntry();
        }
        return bytes.toByteArray();
    }

    @Test
    void listsWhatTheArchiveHoldsWithoutFetchingIt() throws IOException {
        Bytes source = new Bytes(archive());
        try (ZipArchive zip = ZipArchive.open(source, "bundle.zip")) {
            assertEquals(List.of("data/big.root", "data/small.root"),
                    zip.members().stream().map(ZipArchive.Member::name).toList());
            assertEquals(DEFLATABLE.length, zip.member("data/big.root").orElseThrow().size());
            assertFalse(zip.member("data/big.root").orElseThrow().isStored());
            assertTrue(zip.member("data/small.root").orElseThrow().isStored());
        }
        // The index costs the tail and the directory, and nothing else. An
        // archive this small fits inside the tail probe, so the byte count is
        // not interesting here; the number of round trips is.
        assertTrue(source.reads().get() <= 3, "reading the index took " + source.reads());
    }

    @Test
    void inflatesAMemberOutOfTheMiddle() throws IOException {
        try (ZipArchive zip = ZipArchive.open(new Bytes(archive()), "bundle.zip")) {
            assertArrayEquals(DEFLATABLE, zip.read("data/big.root"));
            assertArrayEquals(SMALL, zip.read("data/small.root"));
        }
    }

    @Test
    void readsPartOfAStoredMemberAsOneRange() throws IOException {
        Bytes source = new Bytes(archive());
        try (ZipArchive zip = ZipArchive.open(source, "bundle.zip")) {
            source.reads().set(0);
            assertArrayEquals("histogram".getBytes(StandardCharsets.UTF_8),
                    zip.read("data/small.root", 2, 9));
            // One read for the local header, one for the bytes themselves.
            assertEquals(2, source.reads().get());
            assertArrayEquals(new byte[0], zip.read("data/small.root", 500, 9));
        }
    }

    @Test
    void readsPartOfADeflatedMemberByInflatingItFirst() throws IOException {
        try (ZipArchive zip = ZipArchive.open(new Bytes(archive()), "bundle.zip")) {
            assertArrayEquals(java.util.Arrays.copyOfRange(DEFLATABLE, 100, 140),
                    zip.read("data/big.root", 100, 40));
            assertEquals(DEFLATABLE.length - 10, zip.read("data/big.root", 10, 1 << 20).length);
        }
    }

    @Test
    void readsAnArchiveWithAComment() throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            zip.setComment("written by a tool that likes to sign its work");
            zip.putNextEntry(new ZipEntry("one.root"));
            zip.write(SMALL);
            zip.closeEntry();
        }
        try (ZipArchive zip = ZipArchive.open(new Bytes(bytes.toByteArray()), "commented.zip")) {
            assertArrayEquals(SMALL, zip.read("one.root"));
        }
    }

    @Test
    void readsAZip64ArchiveWhoseFieldsOverflowed() throws IOException {
        // The JDK writes ZIP64 records when told the entry sizes are unknown
        // and the archive is written to a stream, which is the usual way an
        // archive built on the grid ends up with them.
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            ZipEntry entry = new ZipEntry("zip64.root");
            entry.setSize(DEFLATABLE.length);
            zip.putNextEntry(entry);
            zip.write(DEFLATABLE);
            zip.closeEntry();
        }
        byte[] built = bytes.toByteArray();
        try (ZipArchive zip = ZipArchive.open(new Bytes(built), "zip64.zip")) {
            assertArrayEquals(DEFLATABLE, zip.read("zip64.root"));
        }
    }

    @Test
    void saysSoWhenTheMemberIsNotThere() throws IOException {
        try (ZipArchive zip = ZipArchive.open(new Bytes(archive()), "bundle.zip")) {
            XrdException failure = assertThrows(XrdException.class,
                    () -> zip.read("data/absent.root"));
            assertTrue(failure.getMessage().contains("absent.root"), failure.getMessage());
            assertThrows(XrdException.class, () -> zip.read("data/absent.root", 0, 1));
            assertThrows(XrdException.class, () -> zip.read("data/small.root", -1, 1));
        }
    }

    @Test
    void refusesSomethingThatIsNotAnArchive() {
        assertThrows(XrdException.class,
                () -> ZipArchive.open(new Bytes(new byte[4]), "short.zip"));
        assertThrows(XrdException.class,
                () -> ZipArchive.open(new Bytes(new byte[4096]), "zeros.zip"));
    }

    @Test
    void closesTheSourceWhenTheArchiveWillNotOpen() {
        Bytes source = new Bytes(new byte[4096]);
        assertThrows(XrdException.class, () -> ZipArchive.open(source, "zeros.zip"));
        assertTrue(source.closed(), "a source that could not be read was left open");
    }

    @Test
    void noticesAMemberThatCameBackDamaged() throws IOException {
        byte[] built = archive();
        try (ZipArchive zip = ZipArchive.open(new Bytes(built) {
            @Override public byte[] read(long offset, int length) {
                byte[] chunk = super.read(offset, length);
                if (length == SMALL.length) {
                    chunk[0] ^= 0xFF;       // one flipped byte, in the data
                }
                return chunk;
            }
        }, "bundle.zip")) {
            XrdException failure = assertThrows(XrdException.class,
                    () -> zip.read("data/small.root"));
            assertTrue(failure.getMessage().contains("CRC32"), failure.getMessage());
        }
    }

    @Test
    void readsTheMemberAUrlNames() {
        assertEquals(Optional.of("data/big.root"),
                ZipArchive.memberOf("root://host//b.zip?xrdcl.unzip=data/big.root"));
        assertEquals(Optional.of("m.root"),
                ZipArchive.memberOf("root://host//b.zip?authz=abc&xrdcl.unzip=m.root"));
        assertEquals(Optional.empty(), ZipArchive.memberOf("root://host//b.zip"));
        assertEquals(Optional.empty(), ZipArchive.memberOf("root://host//b.zip?xrdcl.unzip="));
        assertEquals(Optional.empty(), ZipArchive.memberOf(null));
    }

    @Test
    void takesTheMemberTagBackOffToGetTheArchive() {
        assertEquals("root://host//b.zip",
                ZipArchive.archiveOf("root://host//b.zip?xrdcl.unzip=m.root"));
        assertEquals("root://host//b.zip?authz=abc",
                ZipArchive.archiveOf("root://host//b.zip?authz=abc&xrdcl.unzip=m.root"));
        assertEquals("root://host//b.zip?authz=abc",
                ZipArchive.archiveOf("root://host//b.zip?authz=abc"));
        assertEquals("root://host//b.zip", ZipArchive.archiveOf("root://host//b.zip"));
    }

    /** A source over an array that counts what was actually asked of it. */
    static class Bytes implements Source {

        private final byte[] content;
        private final AtomicInteger reads = new AtomicInteger();
        private boolean closed;

        Bytes(byte[] content) {
            this.content = content;
        }

        AtomicInteger reads() {
            return reads;
        }

        boolean closed() {
            return closed;
        }

        @Override public long size() {
            return content.length;
        }

        @Override public byte[] read(long offset, int length) {
            reads.incrementAndGet();
            if (offset >= content.length) {
                return new byte[0];
            }
            int end = (int) Math.min(content.length, offset + (long) length);
            return java.util.Arrays.copyOfRange(content, (int) offset, end);
        }

        @Override public void close() {
            closed = true;
        }
    }
}

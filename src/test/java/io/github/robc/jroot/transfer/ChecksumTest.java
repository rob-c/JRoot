package io.github.robc.jroot.transfer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.Adler32;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.robc.jroot.XrdException;

/** The sums a storage element names files by. */
class ChecksumTest {

    private static final byte[] CONTENT =
            "the quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);

    @TempDir
    Path dir;

    @Test
    void computesTheSumTheStorageElementWouldPublish() {
        Adler32 expected = new Adler32();
        expected.update(CONTENT);
        assertEquals(String.format("%08x", expected.getValue()),
                Checksum.of("adler32").update(CONTENT).value());
    }

    @Test
    void writesARunningSumAsEightDigitsEvenWhenItIsShorter() {
        // Adler32 of one NUL is 0x00010001, which is eight digits only
        // because it is padded - and a server that padded it would not
        // match one that did not unless the comparison allowed for it.
        String value = Checksum.of("adler32").update(new byte[] {0}).value();
        assertEquals("00010001", value);
        assertEquals(8, value.length());
    }

    @Test
    void knowsTheOtherAlgorithmsStorageCarries() throws IOException {
        assertEquals("cbf43926", Checksum.of("crc32")
                .update("123456789".getBytes(StandardCharsets.UTF_8)).value());
        assertEquals("e3069283", Checksum.of("crc32c")
                .update("123456789".getBytes(StandardCharsets.UTF_8)).value());
        assertEquals("d41d8cd98f00b204e9800998ecf8427e",
                Checksum.of("md5", new ByteArrayInputStream(new byte[0])));
        assertEquals("da39a3ee5e6b4b0d3255bfef95601890afd80709",
                Checksum.of("sha1", new ByteArrayInputStream(new byte[0])));
        assertEquals(64, Checksum.of("sha256", new ByteArrayInputStream(new byte[0])).length());
    }

    @Test
    void takesTheNamesTheWireUsesForTheOnesTheJdkUses() {
        assertEquals("sha256", Checksum.normalise("SHA-256"));
        assertEquals("adler32", Checksum.normalise(null));
        assertEquals("adler32", Checksum.normalise("  "));
        assertTrue(Checksum.supports("sha512"));
        assertFalse(Checksum.supports("nonesuch"));
        assertThrows(XrdException.class, () -> Checksum.of("nonesuch"));
    }

    @Test
    void comparesLenientlyEnoughToSurviveTwoImplementations() {
        // dCache writes adler32 padded, XRootD writes it bare. The same file.
        assertTrue(Checksum.same("0034d81b", "34d81b"));
        assertTrue(Checksum.same("ABCDEF12", "abcdef12"));
        assertTrue(Checksum.same("00000000", "0"));
        assertFalse(Checksum.same("34d81b", "34d81c"));
        assertFalse(Checksum.same("", "34d81b"));
        assertFalse(Checksum.same(null, "34d81b"));
        assertFalse(Checksum.same("34d81b", null));
    }

    @Test
    void readsAWholeFileAndAWholeSource() throws IOException {
        Path file = Files.write(dir.resolve("f"), CONTENT);
        String expected = Checksum.of("adler32").update(CONTENT).value();
        assertEquals(expected, Checksum.of("adler32", file));
        assertEquals(expected, Checksum.of("adler32", new Bytes(CONTENT)));
        assertEquals(expected, Checksum.of("adler32", new Bytes(CONTENT, true)));
    }

    @Test
    void saysWhichFileItCouldNotRead() {
        assertThrows(XrdException.class, () -> Checksum.of("adler32", dir.resolve("gone")));
    }

    /** A source over an array, optionally one that will not say how big it is. */
    record Bytes(byte[] content, boolean coy) implements Source {

        Bytes(byte[] content) {
            this(content, false);
        }

        @Override public long size() {
            return coy ? -1 : content.length;
        }

        @Override public byte[] read(long offset, int length) {
            if (offset >= content.length) {
                return new byte[0];
            }
            int end = (int) Math.min(content.length, offset + (long) length);
            return java.util.Arrays.copyOfRange(content, (int) offset, end);
        }

        @Override public void close() {
        }
    }
}

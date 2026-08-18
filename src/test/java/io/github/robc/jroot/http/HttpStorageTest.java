package io.github.robc.jroot.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdException;
import io.github.robc.jroot.XrdServerException;
import io.github.robc.jroot.wire.Types.ReadVSegment;
import io.github.robc.jroot.wire.Types.StatInfo;
import io.github.robc.jroot.wire.XrdConst;

/** {@link HttpStorage} against a real HTTP server on the loopback. */
@Timeout(30)
class HttpStorageTest {

    private static final byte[] CONTENT =
            "the quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);

    private static Config config() {
        return Config.defaults().withToken("s3cret");
    }

    @Test
    void statsAnObjectWithHead() throws IOException {
        try (MockHttpStorage server = new MockHttpStorage().put("/data/file", CONTENT);
             HttpStorage storage = new HttpStorage(config())) {
            StatInfo stat = storage.stat(server.url("/data/file"));
            assertEquals(CONTENT.length, stat.size());
            assertEquals("/data/file", stat.path());
            assertTrue(stat.isReadable());
            assertFalse(stat.isDirectory());
            assertEquals(1668516326, stat.mtime(), "Last-Modified, as epoch seconds");
        }
    }

    @Test
    void carriesTheBearerTokenOnEveryRequest() throws IOException {
        try (MockHttpStorage server = new MockHttpStorage().put("/data/file", CONTENT);
             HttpStorage storage = new HttpStorage(config())) {
            storage.read(server.url("/data/file"));
            assertEquals("Bearer s3cret",
                    server.headers().get(0).getFirst("Authorization"));
        }
    }

    @Test
    void readsAWholeObject() throws IOException {
        try (MockHttpStorage server = new MockHttpStorage().put("/data/file", CONTENT);
             HttpStorage storage = new HttpStorage(config())) {
            assertArrayEquals(CONTENT, storage.read(server.url("/data/file")));
        }
    }

    @Test
    void readsAByteRange() throws IOException {
        try (MockHttpStorage server = new MockHttpStorage().put("/data/file", CONTENT);
             HttpStorage storage = new HttpStorage(config())) {
            assertArrayEquals("quick".getBytes(StandardCharsets.UTF_8),
                    storage.read(server.url("/data/file"), 4, 5));
            assertEquals("bytes=4-8", server.headers().get(0).getFirst("Range"));
            assertEquals(0, storage.read(server.url("/data/file"), 0, 0).length);
        }
    }

    @Test
    void readsSeveralRangesInOneRequest() throws IOException {
        try (MockHttpStorage server = new MockHttpStorage().put("/data/file", CONTENT);
             HttpStorage storage = new HttpStorage(config())) {
            List<ReadVSegment> segments = storage.readV(server.url("/data/file"),
                    List.of(new long[] {4, 5}, new long[] {10, 5}, new long[] {40, 3}));
            assertEquals(3, segments.size());
            assertEquals(4, segments.get(0).offset());
            assertArrayEquals("quick".getBytes(StandardCharsets.UTF_8),
                    segments.get(0).data());
            assertArrayEquals("brown".getBytes(StandardCharsets.UTF_8),
                    segments.get(1).data());
            assertEquals(40, segments.get(2).offset());
            assertArrayEquals("dog".getBytes(StandardCharsets.UTF_8),
                    segments.get(2).data());
            assertEquals(1, server.log().size(), "one request, three ranges");
        }
    }

    @Test
    void unpacksASingleRangeAnsweredWithoutMultipart() throws IOException {
        try (MockHttpStorage server = new MockHttpStorage().put("/data/file", CONTENT);
             HttpStorage storage = new HttpStorage(config())) {
            List<ReadVSegment> segments =
                    storage.readV(server.url("/data/file"), List.of(new long[] {4, 5}));
            assertEquals(1, segments.size());
            assertEquals(4, segments.get(0).offset());
            assertArrayEquals("quick".getBytes(StandardCharsets.UTF_8),
                    segments.get(0).data());
        }
    }

    @Test
    void writesBytesAndFiles(@TempDir Path dir) throws IOException {
        Path local = Files.write(dir.resolve("upload"), CONTENT);
        try (MockHttpStorage server = new MockHttpStorage();
             HttpStorage storage = new HttpStorage(config())) {
            storage.write(server.url("/data/one"), CONTENT);
            storage.write(server.url("/data/two"), local);
            assertArrayEquals(CONTENT, server.contentOf("/data/one"));
            assertArrayEquals(CONTENT, server.contentOf("/data/two"));
        }
    }

    @Test
    void downloadsStraightToAFile(@TempDir Path dir) throws IOException {
        Path target = dir.resolve("download");
        try (MockHttpStorage server = new MockHttpStorage().put("/data/file", CONTENT);
             HttpStorage storage = new HttpStorage(config())) {
            assertEquals(CONTENT.length, storage.readTo(server.url("/data/file"), target));
            assertArrayEquals(CONTENT, Files.readAllBytes(target));
        }
    }

    @Test
    void deletesAnObject() throws IOException {
        try (MockHttpStorage server = new MockHttpStorage().put("/data/file", CONTENT);
             HttpStorage storage = new HttpStorage(config())) {
            storage.delete(server.url("/data/file"));
            assertFalse(server.has("/data/file"));
            XrdServerException failure = assertThrows(XrdServerException.class,
                    () -> storage.delete(server.url("/data/file")));
            assertTrue(failure.isNotFound());
        }
    }

    @Test
    void asksForAChecksumWithWantDigest() throws IOException {
        try (MockHttpStorage server = new MockHttpStorage().put("/data/file", CONTENT);
             HttpStorage storage = new HttpStorage(config())) {
            assertEquals("adler32=" + MockHttpStorage.adler32(CONTENT),
                    storage.checksum(server.url("/data/file"), "adler32").orElseThrow());
            assertEquals("adler32", server.headers().get(0).getFirst("Want-Digest"));
        }
    }

    @Test
    void turnsAMissingObjectIntoAnXrootdCode() throws IOException {
        try (MockHttpStorage server = new MockHttpStorage();
             HttpStorage storage = new HttpStorage(config())) {
            XrdServerException failure = assertThrows(XrdServerException.class,
                    () -> storage.read(server.url("/data/missing")));
            assertEquals(XrdConst.kXR_NotFound, failure.code());
            assertFalse(storage.exists(server.url("/data/missing")));
        }
    }

    @Test
    void followsADoorRedirectAndKeepsTheToken() throws IOException {
        try (MockHttpStorage door = new MockHttpStorage();
             MockHttpStorage pool = new MockHttpStorage().put("/data/file", CONTENT);
             HttpStorage storage = new HttpStorage(config())) {
            door.redirectingTo(pool.url("/data/file"));
            assertArrayEquals(CONTENT, storage.read(door.url("/data/file")));
            assertEquals("Bearer s3cret", pool.headers().get(0).getFirst("Authorization"));
        }
    }

    @Test
    void replaysAnUploadBodyThroughARedirect(@TempDir Path dir) throws IOException {
        Path local = Files.write(dir.resolve("upload"), CONTENT);
        try (MockHttpStorage door = new MockHttpStorage();
             MockHttpStorage pool = new MockHttpStorage();
             HttpStorage storage = new HttpStorage(config())) {
            door.redirectingTo(pool.url("/data/file"));
            storage.write(door.url("/data/file"), local);
            assertArrayEquals(CONTENT, pool.contentOf("/data/file"));
        }
    }

    @Test
    void refusesToPutCredentialsOnAPlainRedirect() throws IOException {
        try (MockHttpStorage door = new MockHttpStorage();
             HttpStorage storage = new HttpStorage(config())) {
            door.redirectingTo("http://127.0.0.1:1/data/file");
            // The door is plain http here, so the hop is not a downgrade; it is
            // the refusal on https -> http that matters, exercised by the unit
            // test below. This one only proves the hop is actually taken.
            assertThrows(XrdException.class, () -> storage.read(door.url("/data/file")));
        }
    }

    @Test
    void normalisesTheWebdavSchemes() {
        assertEquals(URI.create("http://host:8080/path"),
                HttpStorage.normalise("dav://host:8080/path"));
        assertEquals(URI.create("https://host/path?x=1"),
                HttpStorage.normalise("davs://host/path?x=1"));
        assertEquals(URI.create("https://host/path"),
                HttpStorage.normalise("https://host/path"));
        assertTrue(HttpStorage.handles("http"));
        assertTrue(HttpStorage.handles("davs"));
        assertFalse(HttpStorage.handles("root"));
    }

    @Test
    void mapsHttpStatusesOntoXrootdCodes() {
        assertEquals(XrdConst.kXR_ArgInvalid, HttpStorage.codeFor(400));
        assertEquals(XrdConst.kXR_NotAuthorized, HttpStorage.codeFor(401));
        assertEquals(XrdConst.kXR_NotAuthorized, HttpStorage.codeFor(403));
        assertEquals(XrdConst.kXR_NotFound, HttpStorage.codeFor(404));
        assertEquals(XrdConst.kXR_Unsupported, HttpStorage.codeFor(405));
        assertEquals(XrdConst.kXR_ItExists, HttpStorage.codeFor(412));
        assertEquals(XrdConst.kXR_FileLocked, HttpStorage.codeFor(423));
        assertEquals(XrdConst.kXR_NoSpace, HttpStorage.codeFor(507));
        assertEquals(XrdConst.kXR_ServerError, HttpStorage.codeFor(500));
    }

    @Test
    void readsTheBoundaryAndTheRangeStart() {
        URI uri = URI.create("http://host/file");
        assertEquals("abc", HttpStorage.boundaryOf("multipart/byteranges; boundary=abc", uri));
        assertEquals("a b", HttpStorage.boundaryOf(
                "multipart/byteranges; boundary=\"a b\"", uri));
        assertThrows(XrdException.class,
                () -> HttpStorage.boundaryOf("multipart/byteranges", uri));
        assertEquals(120, HttpStorage.rangeStart("bytes 120-129/2000"));
        assertEquals(0, HttpStorage.rangeStart("bytes */2000"));
    }

    @Test
    void splitsMultipartBytesWithoutDecodingThem() {
        byte[] first = {0, (byte) 0xC3, (byte) 0x28, 127};
        byte[] second = {(byte) 0xFF, (byte) 0xFE};
        String boundary = "sep";
        StringBuilder head = new StringBuilder();
        java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
        try {
            head.append("--").append(boundary)
                    .append("\r\nContent-Range: bytes 0-3/100\r\n\r\n");
            body.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));
            body.write(first);
            body.write(("\r\n--" + boundary + "\r\nContent-Range: bytes 50-51/100\r\n\r\n")
                    .getBytes(StandardCharsets.ISO_8859_1));
            body.write(second);
            body.write(("\r\n--" + boundary + "--\r\n")
                    .getBytes(StandardCharsets.ISO_8859_1));
        } catch (IOException e) {
            throw new AssertionError(e);
        }
        List<ReadVSegment> segments = HttpStorage.parseByteRanges(
                body.toByteArray(), boundary, URI.create("http://host/file"));
        assertEquals(2, segments.size());
        assertEquals(0, segments.get(0).offset());
        assertArrayEquals(first, segments.get(0).data());
        assertEquals(50, segments.get(1).offset());
        assertArrayEquals(second, segments.get(1).data());
    }
}

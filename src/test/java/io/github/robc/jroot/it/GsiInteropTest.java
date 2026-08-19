package io.github.robc.jroot.it;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.client.XrdClient;
import io.github.robc.jroot.client.XrdFile;
import io.github.robc.jroot.client.XrdUrl;
import io.github.robc.jroot.wire.Types.ReadVSegment;

/**
 * A file up and back down through a real xrootd, over {@code root://} with GSI.
 *
 * <p>Four things are being checked at once, and all four only mean something
 * because the server is the official one: that our GSI exchange is the
 * exchange {@code XrdSecgsi} implements, that an ordinary write lands where a
 * C++ client would have put it, and that {@code kXR_writev} and
 * {@code kXR_readv} — where the framing is most easily got subtly wrong, since
 * one length field describes many pieces — carry exactly the bytes asked for.
 *
 * <p>What arrived is checked against the server's own copy on disk as well as
 * against what we read back, because a client that both writes and reads the
 * same wrong offset agrees with itself perfectly.
 */
@Timeout(180)
class GsiInteropTest {

    private static StockXrootd server;
    private static Config config;

    @BeforeAll
    static void startTheServer() throws Exception {
        assumeTrue(StockXrootd.available(),
                "the official xrootd, xrdgsiproxy and openssl are not installed here");
        server = StockXrootd.start();
        config = Config.defaults().toBuilder()
                .proxyPath(server.proxy())
                .caPath(server.certificates())
                .build();
    }

    @AfterAll
    static void stopTheServer() throws Exception {
        if (server != null) {
            server.close();
        }
    }

    /** The server offers GSI and nothing else, so this also proves the rest of
     *  the class is not quietly running unauthenticated. */
    @Test
    void authenticatesWithGsi() throws Exception {
        try (XrdClient client = new XrdClient(config)) {
            assertEquals("gsi", client.connection(XrdUrl.parse(server.url())).mechanism(),
                    server::log);
        }
    }

    @Test
    void carriesAFileUpAndBackWithOrdinaryReadsAndWrites() throws Exception {
        byte[] payload = payload(1 << 20, 1);
        try (XrdClient client = new XrdClient(config)) {
            try (XrdFile file = client.create(server.url("ordinary.bin"), 0644)) {
                for (int offset = 0; offset < payload.length; offset += CHUNK) {
                    file.write(offset, Arrays.copyOfRange(payload, offset, offset + CHUNK));
                }
                file.sync();
            }
            assertArrayEquals(payload, Files.readAllBytes(server.storage().resolve("ordinary.bin")),
                    "what the server stored is not what we sent");
            try (XrdFile file = client.open(server.url("ordinary.bin"))) {
                assertEquals(payload.length, file.size());
                assertArrayEquals(payload, file.readAll(CHUNK));
                assertArrayEquals(Arrays.copyOfRange(payload, 700_001, 700_001 + 4096),
                        file.read(700_001, 4096), "an unaligned read came back wrong");
            }
        }
    }

    @Test
    void carriesAFileUpAndBackWithVectorReadsAndWrites() throws Exception {
        byte[] payload = payload(1 << 18, 2);
        try (XrdClient client = new XrdClient(config)) {
            try (XrdFile file = client.create(server.url("vector.bin"), 0644)) {
                List<Object[]> chunks = new ArrayList<>();
                for (int offset = 0; offset < payload.length; offset += CHUNK) {
                    chunks.add(new Object[] {(long) offset,
                            Arrays.copyOfRange(payload, offset, offset + CHUNK)});
                }
                file.writeV(chunks, true);
            }
            assertArrayEquals(payload, Files.readAllBytes(server.storage().resolve("vector.bin")),
                    "kXR_writev did not lay the file out the way it was asked to");

            // Read it back in ranges that cut across the writes, so a vector
            // that happened to echo the write boundaries could not pass.
            List<long[]> ranges = new ArrayList<>();
            for (int i = 0; i < 12; i++) {
                ranges.add(new long[] {i * 20_011L, 4093});
            }
            try (XrdFile file = client.open(server.url("vector.bin"))) {
                List<ReadVSegment> segments = file.readV(ranges);
                assertEquals(ranges.size(), segments.size());
                for (int i = 0; i < segments.size(); i++) {
                    ReadVSegment segment = segments.get(i);
                    assertEquals(ranges.get(i)[0], segment.offset());
                    int start = (int) segment.offset();
                    assertArrayEquals(Arrays.copyOfRange(payload, start, start + 4093),
                            segment.data(), "kXR_readv segment " + i + " came back wrong");
                }
            }
        }
    }

    private static final int CHUNK = 1 << 15;

    private static byte[] payload(int size, long seed) {
        byte[] bytes = new byte[size];
        new Random(seed).nextBytes(bytes);
        return bytes;
    }
}

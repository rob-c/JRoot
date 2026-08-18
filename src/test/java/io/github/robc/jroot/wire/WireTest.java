package io.github.robc.jroot.wire;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;

import io.github.robc.jroot.XrdProtocolException;

/** The wire codecs, checked against the byte layout the protocol specifies. */
class WireTest {

    private static final HexFormat HEX = HexFormat.of();

    private static String hex(byte[] data) {
        return HEX.formatHex(data);
    }

    @Test
    void writesEveryWidthBigEndian() {
        assertEquals("7f", hex(new WBuf().u8(0x7F).bytes()));
        assertEquals("0102", hex(new WBuf().u16(0x0102).bytes()));
        assertEquals("01020304", hex(new WBuf().i32(0x01020304).bytes()));
        assertEquals("ffffffff", hex(new WBuf().u32(0xFFFFFFFFL).bytes()));
        assertEquals("00000000deadbeef", hex(new WBuf().i64(0xDEADBEEFL).bytes()));
        assertEquals("000000", hex(new WBuf().zeros(3).bytes()));
        assertEquals("6162", hex(new WBuf().text("ab", false).bytes()));
        assertEquals("616200", hex(new WBuf().text("ab", true).bytes()));
        assertEquals("61620000", hex(new WBuf().padded("ab", 4).bytes()));
        assertEquals("01020000", hex(new WBuf().padded(new byte[] {1, 2}, 4).bytes()));
        assertEquals(4, new WBuf().i32(1).size());
    }

    @Test
    void truncatesOrPadsAFixedWidthField() {
        assertEquals("61626364", hex(new WBuf().padded("abcdef", 4).bytes()));
        assertEquals("61000000", hex(new WBuf().padded("a", 4).bytes()));
        assertEquals(8, new WBuf().padded("rcurrie", 8).size());
    }

    @Test
    void readsBackWhatItWrote() {
        byte[] frame = new WBuf().u8(200).u16(40000).i32(-5).u32(0xFFFFFFFFL)
                .i64(Long.MIN_VALUE).text("name", true).raw(new byte[] {7, 8}).bytes();
        RBuf r = new RBuf(frame, "test");
        assertEquals(200, r.u8());
        assertEquals(40000, r.u16());
        assertEquals(-5, r.i32());
        assertEquals(0xFFFFFFFFL, r.u32());
        assertEquals(Long.MIN_VALUE, r.i64());
        assertEquals("name", r.cstring());
        assertEquals(2, r.remaining());
        assertArrayEquals(new byte[] {7, 8}, r.rest());
        assertEquals(0, r.remaining());
    }

    @Test
    void refusesToReadPastTheEnd() {
        RBuf r = new RBuf(new byte[] {1, 2}, "kXR_stat");
        r.u16();
        XrdProtocolException failure = assertThrows(XrdProtocolException.class, r::i32);
        assertTrue(failure.getMessage().contains("kXR_stat"),
                "the message should name the response being read: " + failure.getMessage());
    }

    @Test
    void buildsTheClientHandshake() {
        // 0,0,0,4,2012 — the bytes every xrootd server expects first.
        assertEquals("00000000000000000000000000000004000007dc",
                hex(XrdRequest.HANDSHAKE));
        assertEquals(20, XrdRequest.HANDSHAKE.length);
    }

    @Test
    void framesARequestAsHeaderThenPayload() {
        byte[] frame = new Requests.Stat("/store/file").encode(0x1234);
        assertEquals(0x1234, ((frame[0] & 0xFF) << 8) | (frame[1] & 0xFF));
        assertEquals(XrdConst.kXR_stat, ((frame[2] & 0xFF) << 8) | (frame[3] & 0xFF));
        assertEquals(XrdConst.REQUEST_HDRLEN + "/store/file".length(), frame.length);
        int dlen = ((frame[20] & 0xFF) << 24) | ((frame[21] & 0xFF) << 16)
                | ((frame[22] & 0xFF) << 8) | (frame[23] & 0xFF);
        assertEquals("/store/file".length(), dlen);
        assertEquals("/store/file", new String(frame, XrdConst.REQUEST_HDRLEN,
                dlen, StandardCharsets.UTF_8));
    }

    @Test
    void putsOpenModeAndOptionsWhereTheyBelong() {
        byte[] frame = new Requests.Open("/f", XrdConst.kXR_open_read, 0640).encode(1);
        // params: mode[2] options[2] reserved[12]
        assertEquals(0640, ((frame[4] & 0xFF) << 8) | (frame[5] & 0xFF));
        assertEquals(XrdConst.kXR_open_read, ((frame[6] & 0xFF) << 8) | (frame[7] & 0xFF));
    }

    @Test
    void putsTheModeAtTheEndOfAMkdirsParameters() {
        byte[] plain = new Requests.Mkdir("/d", 0755, false).encode(1);
        byte[] parents = new Requests.Mkdir("/d", 0755, true).encode(1);
        assertEquals(0, plain[4]);
        assertEquals(XrdConst.kXR_mkdirpath, parents[4]);
        assertEquals(0755, ((plain[18] & 0xFF) << 8) | (plain[19] & 0xFF));
    }

    @Test
    void carriesTheHandleOffsetAndLengthOfARead() {
        byte[] handle = {1, 2, 3, 4};
        byte[] frame = new Requests.Read(handle, 0x0102030405L, 8192).encode(1);
        assertEquals("01020304", hex(java.util.Arrays.copyOfRange(frame, 4, 8)));
        assertEquals("00000001" + "02030405", hex(java.util.Arrays.copyOfRange(frame, 8, 16)));
        assertEquals(8192, ((frame[16] & 0xFF) << 24) | ((frame[17] & 0xFF) << 16)
                | ((frame[18] & 0xFF) << 8) | (frame[19] & 0xFF));
    }

    @Test
    void countsAWritesPayloadInItsLength() {
        byte[] data = "payload".getBytes(StandardCharsets.UTF_8);
        byte[] frame = new Requests.Write(new byte[] {9, 9, 9, 9}, 0, data).encode(1);
        assertEquals(XrdConst.REQUEST_HDRLEN + data.length, frame.length);
        assertArrayEquals(data, java.util.Arrays.copyOfRange(frame,
                XrdConst.REQUEST_HDRLEN, frame.length));
    }

    @Test
    void doesNotCountAWritevsTrailer() {
        byte[] data = "0123456789".getBytes(StandardCharsets.UTF_8);
        byte[] frame = new Requests.WriteV(
                java.util.List.of(new Requests.WriteSegment(new byte[] {1, 1, 1, 1}, 0, data)),
                false).encode(1);
        int dlen = ((frame[20] & 0xFF) << 24) | ((frame[21] & 0xFF) << 16)
                | ((frame[22] & 0xFF) << 8) | (frame[23] & 0xFF);
        assertEquals(16, dlen, "dlen counts the descriptor block only");
        assertEquals(XrdConst.REQUEST_HDRLEN + 16 + data.length, frame.length,
                "the data still follows the frame");
    }

    @Test
    void namesTheApplicationInASetDirective() {
        byte[] frame = Requests.Set.appId("jroot").encode(1);
        assertEquals("appid jroot", new String(frame, XrdConst.REQUEST_HDRLEN,
                frame.length - XrdConst.REQUEST_HDRLEN, StandardCharsets.UTF_8));
    }

    @Test
    void wrapsAWriteInsideACheckpoint() {
        byte[] handle = {4, 3, 2, 1};
        byte[] frame = Requests.Chkpoint.exec(handle,
                new Requests.Write(handle, 0, new byte[] {1})).encode(1);
        assertEquals(XrdConst.kXR_chkpoint, ((frame[2] & 0xFF) << 8) | (frame[3] & 0xFF));
        assertEquals(XrdConst.kXR_ckpXeq, frame[19]);
        // The payload is a complete kXR_write frame on stream 0.
        assertEquals(0, frame[XrdConst.REQUEST_HDRLEN]);
        assertEquals(XrdConst.kXR_write,
                ((frame[XrdConst.REQUEST_HDRLEN + 2] & 0xFF) << 8)
                        | (frame[XrdConst.REQUEST_HDRLEN + 3] & 0xFF));
    }

    @Test
    void refusesToCheckpointSomethingThatIsNotAWrite() {
        assertThrows(IllegalArgumentException.class, () -> Requests.Chkpoint.exec(
                new byte[] {1, 1, 1, 1}, new Requests.Stat("/f")));
    }

    @Test
    void signsOnlyTheRequestsThatChangeSomething() {
        assertTrue(new Requests.Open("/f", 0, 0).signed());
        assertTrue(new Requests.Rm("/f").signed());
        assertTrue(new Requests.Mkdir("/d", 0755, false).signed());
        assertTrue(new Requests.Write(new byte[4], 0, new byte[0]).signed());
        assertEquals(false, new Requests.Stat("/f").signed());
        assertEquals(false, new Requests.Read(new byte[4], 0, 1).signed());
    }

    @Test
    void decodesAResponseHeader() {
        ResponseHeader header = ResponseHeader.decode(
                new WBuf().u16(7).u16(XrdConst.kXR_oksofar).i32(1024).bytes());
        assertEquals(7, header.streamId());
        assertEquals(XrdConst.kXR_oksofar, header.status());
        assertEquals(1024, header.dataLength());
        assertThrows(XrdProtocolException.class,
                () -> ResponseHeader.decode(new byte[] {0, 1, 2}));
        assertThrows(XrdProtocolException.class, () -> ResponseHeader.decode(
                new WBuf().u16(1).u16(XrdConst.kXR_ok).i32(-1).bytes()));
    }

    @Test
    void namesTheRequestsItKnows() {
        assertEquals("kXR_stat", XrdConst.requestName(XrdConst.kXR_stat));
        assertEquals("kXR_pgwrite", XrdConst.requestName(XrdConst.kXR_pgwrite));
        assertTrue(XrdConst.requestName(31337).contains("31337"));
    }
}

package io.github.robc.jroot.wire;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;

import io.github.robc.jroot.XrdProtocolException;
import io.github.robc.jroot.wire.Types.DirEntry;
import io.github.robc.jroot.wire.Types.LocationInfo;
import io.github.robc.jroot.wire.Types.PrepareStatus;
import io.github.robc.jroot.wire.Types.ReadVSegment;
import io.github.robc.jroot.wire.Types.RedirectInfo;
import io.github.robc.jroot.wire.Types.SpaceInfo;
import io.github.robc.jroot.wire.Types.StatInfo;
import io.github.robc.jroot.wire.Types.StatusInfo;

/** The response parsers, against the bodies servers actually send. */
class ResponsesTest {

    private static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void readsAnErrorCodeAndMessage() {
        Responses.ErrorInfo error = Responses.parseError(
                new WBuf().i32(XrdConst.kXR_NotFound).text("no such file", true).bytes());
        assertEquals(XrdConst.kXR_NotFound, error.code());
        assertEquals("no such file", error.message());
    }

    @Test
    void splitsARedirectIntoHostPortAndOpaque() {
        RedirectInfo redirect = Responses.parseRedirect(
                new WBuf().i32(1094).text("pool7.example.org?xrd.k=abc&t=1", false).bytes());
        assertEquals("pool7.example.org", redirect.host());
        assertEquals(1094, redirect.port());
        assertEquals("xrd.k=abc&t=1", redirect.opaque());
        assertFalse(redirect.requiresTls());
        assertEquals(1094, redirect.actualPort());
    }

    @Test
    void readsARedirectThatAsksForTls() {
        // A negative port is how a manager says "come back over TLS".
        RedirectInfo redirect = Responses.parseRedirect(
                new WBuf().i32(-1094).text("pool7", false).bytes());
        assertTrue(redirect.requiresTls());
        assertEquals(1094, redirect.actualPort());
    }

    @Test
    void refusesARedirectWithNoHost() {
        assertThrows(XrdProtocolException.class, () -> Responses.parseRedirect(
                new WBuf().i32(1094).text("?only=opaque", false).bytes()));
    }

    @Test
    void readsAWaitAndItsReason() {
        Types.WaitInfo wait = Responses.parseWait(
                new WBuf().i32(5).text("staging from tape", true).bytes());
        assertEquals(5, wait.seconds());
        assertEquals("staging from tape", wait.message());
        assertEquals(30, Responses.parseWaitResp(new WBuf().i32(30).bytes()).seconds());
    }

    @Test
    void readsAStatusHeaderAndItsTail() {
        byte[] body = new WBuf().u32(0xDEADBEEFL).u16(9)
                .u8(XrdConst.kXR_pgwrite - XrdConst.kXR_1stRequest)
                .u8(0).zeros(4).i32(3).raw(new byte[] {1, 2, 3}).bytes();
        StatusInfo status = Responses.parseStatus(body);
        assertEquals(0xDEADBEEFL, status.crc32c());
        assertEquals(9, status.streamId());
        assertEquals(XrdConst.kXR_pgwrite, status.requestId());
        assertTrue(status.isFinal());
        assertEquals(3, status.dataLength());
        assertArrayEquals(new byte[] {1, 2, 3}, status.info());
    }

    @Test
    void readsAStatLine() {
        StatInfo stat = Responses.parseStat(
                utf8("2718281828 1048576 " + (XrdConst.kXR_readable | XrdConst.kXR_writable)
                        + " 1668516326"), "/store/file");
        assertEquals("2718281828", stat.id());
        assertEquals(1048576, stat.size());
        assertEquals(1668516326, stat.mtime());
        assertEquals("/store/file", stat.path());
        assertTrue(stat.isReadable());
        assertTrue(stat.isWritable());
        assertFalse(stat.isDirectory());
    }

    @Test
    void refusesAStatLineWithTooFewFields() {
        assertThrows(XrdProtocolException.class,
                () -> Responses.parseStat(utf8("id 100 4"), "/f"));
        assertThrows(XrdProtocolException.class,
                () -> Responses.parseStat(utf8("id big 4 0"), "/f"));
    }

    @Test
    void readsAPlainDirectoryListing() {
        List<DirEntry> entries = Responses.parseDirlist(
                utf8("one.root\ntwo.root\n"), "/store");
        assertEquals(List.of("one.root", "two.root"),
                entries.stream().map(DirEntry::name).toList());
        assertTrue(entries.get(0).stat().isEmpty());
        assertEquals("/store", entries.get(0).parent());
    }

    @Test
    void readsAListingWithStatAndDropsTheDotEntry() {
        List<DirEntry> entries = Responses.parseDirlist(
                utf8(".\n0 0 " + XrdConst.kXR_isDir + " 0\n"
                        + "one.root\nid1 4096 0 11\n"
                        + "sub\nid2 0 " + XrdConst.kXR_isDir + " 12\n"), "/store");
        assertEquals(2, entries.size());
        assertEquals(4096, entries.get(0).stat().orElseThrow().size());
        assertEquals("/store/one.root", entries.get(0).stat().orElseThrow().path());
        assertTrue(entries.get(1).isDirectory());
    }

    @Test
    void refusesAListingEntryThatIsAPath() {
        assertThrows(XrdProtocolException.class, () -> Responses.parseDirlist(
                utf8("../../.ssh/authorized_keys\n"), "/store"));
        assertThrows(XrdProtocolException.class, () -> Responses.parseDirlist(
                utf8(".\n0 0 2 0\n..\nid 0 2 0\n"), "/store"));
    }

    @Test
    void readsTheLocationsOfAFile() {
        List<LocationInfo> locations = Responses.parseLocate(
                utf8("Sr192.168.0.1:1094 Mw192.168.0.2:1094"));
        assertEquals(2, locations.size());
        assertTrue(locations.get(0).isServer());
        assertEquals("192.168.0.1:1094", locations.get(0).address());
        assertTrue(locations.get(1).isManager());
        assertTrue(locations.get(1).isWritable());
    }

    @Test
    void readsAnOpenReplyWithItsStat() {
        byte[] body = new WBuf().raw(new byte[] {1, 2, 3, 4})
                .i32(XrdConst.kXR_pgPageSZ).text("adlr", false)
                .text("id 512 0 7", false).bytes();
        Types.OpenInfo open = Responses.parseOpen(body, "/store/file");
        assertArrayEquals(new byte[] {1, 2, 3, 4}, open.fhandle());
        assertEquals(XrdConst.kXR_pgPageSZ, open.compressionPageSize());
        assertEquals("adlr", open.compressionAlgorithm());
        assertEquals(512, open.stat().orElseThrow().size());
    }

    @Test
    void readsAnOpenReplyThatCarriedOnlyAHandle() {
        Types.OpenInfo open = Responses.parseOpen(new byte[] {9, 8, 7, 6}, "/f");
        assertArrayEquals(new byte[] {9, 8, 7, 6}, open.fhandle());
        assertTrue(open.stat().isEmpty());
    }

    @Test
    void lowercasesAChecksum() {
        Types.ChecksumInfo checksum = Responses.parseChecksum(utf8("ADLER32 0BADCAFE\n"));
        assertEquals("adler32", checksum.algorithm());
        assertEquals("0badcafe", checksum.value());
        assertThrows(XrdProtocolException.class,
                () -> Responses.parseChecksum(utf8("adler32")));
    }

    @Test
    void readsSpaceFromOssCgi() {
        SpaceInfo space = Responses.parseSpace(utf8(
                "oss.cgroup=public&oss.space=1000000&oss.free=400000"
                        + "&oss.maxf=250000&oss.used=600000&oss.quota=900000"));
        assertEquals("public", space.name());
        assertEquals(1000000, space.total());
        assertEquals(400000, space.free());
        assertEquals(250000, space.largestFree());
        assertEquals(600000, space.used());
        assertEquals(900000, space.quota());
    }

    @Test
    void readsSpaceFromAServerThatOmittedTheQuota() {
        SpaceInfo space = Responses.parseSpace(utf8("oss.space=10\noss.free=5"));
        assertEquals(10, space.total());
        assertEquals(-1, space.quota(), "no quota is not a quota of zero");
        assertThrows(XrdProtocolException.class,
                () -> Responses.parseSpace(utf8("oss.space=lots")));
    }

    @Test
    void unpacksAVectorReadIntoItsSegments() {
        byte[] first = "aaaa".getBytes(StandardCharsets.UTF_8);
        byte[] second = "bb".getBytes(StandardCharsets.UTF_8);
        byte[] body = new WBuf()
                .raw(new byte[] {1, 1, 1, 1}).i32(first.length).i64(0).raw(first)
                .raw(new byte[] {1, 1, 1, 1}).i32(second.length).i64(4096).raw(second)
                .bytes();
        List<ReadVSegment> segments = Responses.parseReadV(body);
        assertEquals(2, segments.size());
        assertEquals(0, segments.get(0).offset());
        assertArrayEquals(first, segments.get(0).data());
        assertEquals(4096, segments.get(1).offset());
        assertArrayEquals(second, segments.get(1).data());
    }

    @Test
    void refusesAVectorReadSegmentWithANegativeLength() {
        byte[] body = new WBuf().raw(new byte[] {1, 1, 1, 1}).i32(-1).i64(0).bytes();
        assertThrows(XrdProtocolException.class, () -> Responses.parseReadV(body));
    }

    @Test
    void readsExtendedAttributes() {
        byte[] value = "17".getBytes(StandardCharsets.UTF_8);
        byte[] body = new WBuf().u8(0).u8(2)
                .u16(0).text("user.count", true).i32(value.length).raw(value)
                .u16(0).text("user.owner", true).i32(0)
                .bytes();
        Types.FattrResult result = Responses.parseFattr(body, true);
        assertEquals(0, result.errors());
        assertEquals(2, result.items().size());
        assertEquals("user.count", result.items().get(0).name());
        assertArrayEquals(value, result.items().get(0).value());
        assertEquals("user.owner", result.items().get(1).name());
    }

    @Test
    void readsTheProtocolVersionAndFlags() {
        Types.ProtocolInfo protocol = Responses.parseProtocol(new WBuf()
                .i32(XrdConst.kXR_PROTOCOLVERSION)
                .i32(XrdConst.kXR_DataServer | XrdConst.kXR_haveTLS).bytes());
        assertEquals(XrdConst.kXR_PROTOCOLVERSION, protocol.version());
        assertTrue(protocol.hasTls());
        assertFalse(protocol.demandsTls());
    }

    @Test
    void readsTheSessionIdAndSecurityOffer() {
        byte[] body = new WBuf().zeros(XrdConst.SESSION_ID_LEN)
                .text("&P=gsi,v:10400,c:ssl,ca:abc&P=unix", true).bytes();
        Types.LoginInfo login = Responses.parseLogin(body);
        assertEquals(XrdConst.SESSION_ID_LEN, login.sessionId().length);
        assertEquals(List.of("gsi", "unix"), login.mechanisms());
    }

    @Test
    void refusesAPathIdOfZeroFromBind() {
        assertEquals(3, Responses.parseBind(new byte[] {3}));
        assertThrows(XrdProtocolException.class,
                () -> Responses.parseBind(new byte[] {0}));
    }

    @Test
    void readsCheckpointLimits() {
        Types.ChkpointLimits limits =
                Responses.parseChkpoint(new WBuf().u32(1 << 20).u32(4096).bytes());
        assertEquals(1 << 20, limits.maxBytes());
        assertEquals(4096, limits.usedBytes());
        assertEquals(0, Responses.parseChkpoint(new byte[0]).maxBytes());
    }

    @Test
    void readsVfsAndStatxAnswers() {
        Types.VfsInfo vfs = Responses.parseStatVfs(utf8("2 100 40 3 200 60"));
        assertEquals(2, vfs.nodesRw());
        assertEquals(100, vfs.freeRw());
        assertEquals(40, vfs.utilizationRw());
        assertArrayEquals(new int[] {XrdConst.kXR_isDir, XrdConst.kXR_readable},
                Responses.parseStatx(new byte[] {XrdConst.kXR_isDir, XrdConst.kXR_readable}));
    }
    @Test
    void readsTheJsonAServerAnswersAPrepareQueryWith() {
        List<PrepareStatus> statuses = Responses.parsePrepareStatus(utf8("""
                {"request_id":"7f3","responses":[
                  {"path":"/store/one","path_exists":1,"on_tape":1,"online":0,
                   "requested":1,"has_reqid":1,"req_time":"1700000000",
                   "error_text":"","state":"staging"},
                  {"path":"/store/two","path_exists":1,"on_tape":0,"online":1,
                   "requested":0,"has_reqid":0,"req_time":"","error_text":"",
                   "state":"online"}]}"""),
                List.of("/store/one", "/store/two"));
        assertEquals(2, statuses.size());
        assertTrue(statuses.get(0).onTape());
        assertFalse(statuses.get(0).online());
        assertTrue(statuses.get(0).requested());
        assertEquals("1700000000", statuses.get(0).requestedAt());
        assertEquals("staging", statuses.get(0).state());
        assertTrue(statuses.get(1).online());
        assertFalse(statuses.get(1).hasRequestId());
    }

    @Test
    void answersInTheOrderTheCallerAsked() {
        List<PrepareStatus> statuses = Responses.parsePrepareStatus(utf8(
                "{\"responses\":[{\"path\":\"/b\",\"online\":true},"
                        + "{\"path\":\"/a\",\"online\":true}]}"),
                List.of("/a", "/b"));
        assertEquals(List.of("/a", "/b"),
                statuses.stream().map(PrepareStatus::path).toList());
    }

    @Test
    void saysSoAboutAPathTheServerNeverMentioned() {
        List<PrepareStatus> statuses = Responses.parsePrepareStatus(
                utf8("{\"responses\":[{\"path\":\"/a\",\"online\":true}]}"),
                List.of("/a", "/missing"));
        assertTrue(statuses.get(0).online());
        assertFalse(statuses.get(1).exists());
        assertEquals("not part of this request", statuses.get(1).error());
    }

    @Test
    void takesABareArrayAndAnEmptyBodyAlike() {
        assertEquals(1, Responses.parsePrepareStatus(
                utf8("[{\"path\":\"/a\",\"on_tape\":\"yes\"}]"), List.of()).size());
        assertTrue(Responses.parsePrepareStatus(new byte[0], List.of()).isEmpty());
        assertEquals("not part of this request",
                Responses.parsePrepareStatus(new byte[0], List.of("/a")).get(0).error());
    }

    @Test
    void refusesAPrepareAnswerThatIsNotJson() {
        assertThrows(XrdProtocolException.class,
                () -> Responses.parsePrepareStatus(utf8("staging /store/one"), List.of()));
    }
}
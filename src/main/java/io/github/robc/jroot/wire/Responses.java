package io.github.robc.jroot.wire;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.github.robc.jroot.XrdProtocolException;
import io.github.robc.jroot.util.Json;
import io.github.robc.jroot.wire.Types.AttnInfo;
import io.github.robc.jroot.wire.Types.ChecksumInfo;
import io.github.robc.jroot.wire.Types.DirEntry;
import io.github.robc.jroot.wire.Types.FattrItem;
import io.github.robc.jroot.wire.Types.FattrResult;
import io.github.robc.jroot.wire.Types.LocationInfo;
import io.github.robc.jroot.wire.Types.LoginInfo;
import io.github.robc.jroot.wire.Types.OpenInfo;
import io.github.robc.jroot.wire.Types.PrepareStatus;
import io.github.robc.jroot.wire.Types.ProtocolInfo;
import io.github.robc.jroot.wire.Types.ReadVSegment;
import io.github.robc.jroot.wire.Types.RedirectInfo;
import io.github.robc.jroot.wire.Types.SpaceInfo;
import io.github.robc.jroot.wire.Types.StatInfo;
import io.github.robc.jroot.wire.Types.StatusInfo;
import io.github.robc.jroot.wire.Types.VfsInfo;
import io.github.robc.jroot.wire.Types.WaitInfo;

/**
 * Response body decoders. Each method decodes the bytes after the 8-byte
 * {@code ServerResponseHdr}; status dispatch is the connection's job.
 */
public final class Responses {

    private Responses() {}

    private static String textOf(byte[] data) {
        int end = 0;
        while (end < data.length && data[end] != 0) {
            end++;
        }
        return new String(data, 0, end, StandardCharsets.UTF_8);
    }

    /** {@code kXR_error}: code then NUL-terminated message. */
    public record ErrorInfo(int code, String message) {}

    public static ErrorInfo parseError(byte[] data) {
        RBuf r = new RBuf(data, "kXR_error");
        return new ErrorInfo(r.i32(), r.cstring());
    }

    public static RedirectInfo parseRedirect(byte[] data) {
        RBuf r = new RBuf(data, "kXR_redirect");
        int port = r.i32();
        String target = textOf(r.rest());
        int q = target.indexOf('?');
        String host = q < 0 ? target : target.substring(0, q);
        String opaque = q < 0 ? "" : target.substring(q + 1);
        if (host.isEmpty()) {
            throw new XrdProtocolException("kXR_redirect names no host to redirect to");
        }
        return new RedirectInfo(host, port, opaque);
    }

    public static WaitInfo parseWait(byte[] data) {
        RBuf r = new RBuf(data, "kXR_wait");
        return new WaitInfo(r.i32(), r.cstring());
    }

    public static WaitInfo parseWaitResp(byte[] data) {
        RBuf r = new RBuf(data, "kXR_waitresp");
        return new WaitInfo(r.i32(), "");
    }

    public static AttnInfo parseAttn(byte[] data) {
        RBuf r = new RBuf(data, "kXR_attn");
        return new AttnInfo(r.i32(), r.rest());
    }

    /** Body of {@code kXR_status}: crc[4] sid[2] reqid[1] resptype[1] rsvd[4]
     *  dlen[4], then a request-specific info tail. */
    public static StatusInfo parseStatus(byte[] data) {
        RBuf r = new RBuf(data, "kXR_status");
        long crc = r.u32();
        int sid = r.u16();
        int reqid = r.u8() + XrdConst.kXR_1stRequest;
        int resptype = r.u8();
        r.skip(4);
        int dlen = r.i32();
        return new StatusInfo(crc, sid, reqid, resptype, dlen, r.rest());
    }

    // ---------------------------------------------------------------
    // Session bring-up
    // ---------------------------------------------------------------

    /**
     * Locate the {@code ServerResponseReqs_Protocol} record inside a
     * {@code kXR_protocol} body's post-flags trailer, returning the bytes
     * from its {@code 'S'} tag on, or null. Two on-wire shapes carry it:
     * the spec shape where the record is the whole trailer, and a vendor
     * shape that prefixes a 4-byte security-methods header plus 8-byte
     * method entries. Anything else reads as "no security requirements",
     * which is what the reference client does too.
     */
    private static byte[] findSecReqs(byte[] trailer) {
        if (trailer.length >= 6 && trailer[0] == 'S') {
            return trailer;
        }
        if (trailer.length >= 4) {
            int off = 4 + (trailer[2] & 0xFF) * 8;
            if (trailer.length >= off + 6 && trailer[off] == 'S') {
                byte[] out = new byte[trailer.length - off];
                System.arraycopy(trailer, off, out, 0, out.length);
                return out;
            }
        }
        return null;
    }

    public static ProtocolInfo parseProtocol(byte[] data) {
        RBuf r = new RBuf(data, "kXR_protocol");
        int version = r.i32();
        int flags = r.i32();
        int seclvl = XrdConst.kXR_secNone;
        int secver = 0;
        int secopt = 0;
        Map<Integer, Integer> overrides = new HashMap<>();
        byte[] reqs = findSecReqs(r.rest());
        if (reqs != null) {
            // 'S' rsvd secver secopt seclvl secvsz, then secvec pairs.
            secver = reqs[2] & 0xFF;
            secopt = reqs[3] & 0xFF;
            seclvl = reqs[4] & 0xFF;
            int secvsz = reqs[5] & 0xFF;
            int pos = 6;
            for (int i = 0; i < secvsz && pos + 2 <= reqs.length; i++, pos += 2) {
                overrides.put((reqs[pos] & 0xFF) + XrdConst.kXR_1stRequest,
                        reqs[pos + 1] & 0xFF);
            }
        }
        return new ProtocolInfo(version, flags, seclvl, secver, secopt, Map.copyOf(overrides));
    }

    public static LoginInfo parseLogin(byte[] data) {
        RBuf r = new RBuf(data, "kXR_login");
        byte[] sessid = r.bytes(Math.min(XrdConst.SESSION_ID_LEN, r.remaining()));
        return new LoginInfo(sessid, textOf(r.rest()));
    }

    /** The path id {@code kXR_bind} assigned. Zero is refused: it is how
     *  every request spells "the control link". */
    public static int parseBind(byte[] data) {
        int pathid = new RBuf(data, "kXR_bind").u8();
        if (pathid == 0) {
            throw new XrdProtocolException("kXR_bind returned path id 0, which is the control link");
        }
        return pathid;
    }

    /** {@code kXR_chkpoint} with {@code kXR_ckpQuery}: two 32-bit byte counts. */
    public static Types.ChkpointLimits parseChkpoint(byte[] data) {
        if (data.length < 8) {
            return new Types.ChkpointLimits(0, 0);
        }
        RBuf r = new RBuf(data, "kXR_chkpoint");
        return new Types.ChkpointLimits(r.u32(), r.u32());
    }

    // ---------------------------------------------------------------
    // Metadata
    // ---------------------------------------------------------------

    private static StatInfo statFields(String text, String path) {
        String[] parts = text.trim().split("\\s+");
        if (parts.length < 4) {
            throw new XrdProtocolException(
                    "kXR_stat returned " + parts.length + " fields, expected >= 4: " + text);
        }
        try {
            return new StatInfo(parts[0], Long.parseLong(parts[1]),
                    Integer.parseInt(parts[2]), Long.parseLong(parts[3]), path);
        } catch (NumberFormatException e) {
            throw new XrdProtocolException("unparseable kXR_stat line: " + text, e);
        }
    }

    /** {@code kXR_stat}: a space-separated {@code id size flags modtime} line. */
    public static StatInfo parseStat(byte[] data, String path) {
        return statFields(textOf(data), path);
    }

    public static VfsInfo parseStatVfs(byte[] data) {
        String[] parts = textOf(data).trim().split("\\s+");
        if (parts.length < 6) {
            throw new XrdProtocolException(
                    "kXR_stat vfs returned " + parts.length + " fields, expected 6");
        }
        return new VfsInfo(Long.parseLong(parts[0]), Long.parseLong(parts[1]),
                Integer.parseInt(parts[2]), Long.parseLong(parts[3]),
                Long.parseLong(parts[4]), Integer.parseInt(parts[5]));
    }

    /** {@code kXR_statx}: one flags byte per requested path. */
    public static int[] parseStatx(byte[] data) {
        int[] out = new int[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = data[i] & 0xFF;
        }
        return out;
    }

    /**
     * Refuse a listing entry that is not a single path component. Consumers
     * join these names onto a directory, so a server that answers
     * {@code ../../.ssh/authorized_keys} would have a recursive download
     * write outside the directory it was pointed at.
     */
    private static String checkedName(String name, String path) {
        if (name.contains("/") || name.equals("..")) {
            throw new XrdProtocolException(
                    "kXR_dirlist entry \"" + name + "\" in \"" + path + "\" is not a name");
        }
        return name;
    }

    /**
     * {@code kXR_dirlist}. Plain mode is one name per line. With
     * {@code kXR_dstat} the server emits a leading {@code ".\n<stat>"} entry
     * followed by {@code name\n<stat>} pairs; the dot entry describes the
     * directory itself and is dropped. The dot entry is also how a server
     * says it honoured the request, so the reply decides, not the flag sent.
     */
    public static List<DirEntry> parseDirlist(byte[] data, String path) {
        String text = textOf(data);
        List<String> lines = new ArrayList<>();
        for (String line : text.split("\n")) {
            if (!line.isEmpty()) {
                lines.add(line);
            }
        }
        List<DirEntry> entries = new ArrayList<>();
        if (lines.isEmpty() || !lines.get(0).equals(".")) {
            for (String name : lines) {
                entries.add(new DirEntry(checkedName(name, path), path, Optional.empty()));
            }
            return entries;
        }
        for (int i = 0; i + 1 < lines.size(); i += 2) {
            String name = lines.get(i);
            String statLine = lines.get(i + 1);
            if (name.equals(".")) {
                continue;
            }
            checkedName(name, path);
            String childPath = path.endsWith("/") ? path + name : path + "/" + name;
            entries.add(new DirEntry(name, path, Optional.of(statFields(statLine, childPath))));
        }
        return entries;
    }

    public static List<LocationInfo> parseLocate(byte[] data) {
        List<LocationInfo> out = new ArrayList<>();
        for (String token : textOf(data).trim().split("\\s+")) {
            if (token.length() >= 3) {
                out.add(new LocationInfo(token.substring(2), token.charAt(0), token.charAt(1)));
            }
        }
        return out;
    }

    public static OpenInfo parseOpen(byte[] data, String path) {
        RBuf r = new RBuf(data, "kXR_open");
        byte[] fhandle = r.bytes(XrdConst.FHANDLE_LEN);
        if (r.remaining() < 8) {
            return new OpenInfo(fhandle, Optional.empty(), 0, "");
        }
        int page = r.i32();
        String algo = textOf(r.bytes(4));
        String tail = textOf(r.rest()).trim();
        Optional<StatInfo> stat = tail.isEmpty() ? Optional.empty()
                : Optional.of(statFields(tail, path));
        return new OpenInfo(fhandle, stat, page, algo);
    }

    /** {@code kXR_query} with {@code kXR_Qcksum}: {@code "<type> <value>"}. */
    public static ChecksumInfo parseChecksum(byte[] data) {
        String text = textOf(data).trim();
        int sp = text.indexOf(' ');
        if (sp <= 0 || sp == text.length() - 1) {
            throw new XrdProtocolException("malformed checksum response: " + text);
        }
        return new ChecksumInfo(text.substring(0, sp).toLowerCase(),
                text.substring(sp + 1).trim().toLowerCase());
    }

    /**
     * {@code kXR_query} with {@code kXR_QPrep}: the staging state of each
     * file asked about.
     *
     * <p>Unlike every other query, this one answers with a JSON document
     * rather than a packed structure or a CGI string. Keys the server did not
     * send keep their default and keys this does not know about are ignored,
     * because the format has gained fields between releases and a client that
     * insisted on the set it was written against would break on the next one.
     *
     * <p>The answer is ordered by {@code paths} when there are any: a file
     * the reply says nothing about comes back as one the request never named,
     * rather than being quietly dropped. The caller asked about it, and
     * silence is an answer they would otherwise have to guess at.
     */
    public static List<PrepareStatus> parsePrepareStatus(byte[] data, List<String> paths) {
        String text = textOf(data).trim();
        Object document = Json.parse(text.isEmpty() ? "{}" : text);
        Object entries = document instanceof List ? document
                : Json.object(document).getOrDefault("responses",
                        Json.object(document).get("files"));
        Map<String, PrepareStatus> found = new LinkedHashMap<>();
        for (Object entry : Json.array(entries)) {
            String path = Json.text(entry, "path");
            found.put(path, new PrepareStatus(path,
                    Json.flag(entry, "path_exists"),
                    Json.flag(entry, "on_tape"),
                    Json.flag(entry, "online"),
                    Json.flag(entry, "requested"),
                    Json.flag(entry, "has_reqid"),
                    Json.text(entry, "req_time"),
                    Json.text(entry, "error_text"),
                    Json.text(entry, "state")));
        }
        return ordered(found, paths);
    }

    /** One status per path asked about, in that order — which is the shape
     *  the HTTP tape API answers in too, so it is shared rather than copied. */
    public static List<PrepareStatus> ordered(Map<String, PrepareStatus> found, List<String> paths) {
        if (paths.isEmpty()) {
            return List.copyOf(found.values());
        }
        List<PrepareStatus> out = new ArrayList<>(paths.size());
        for (String path : paths) {
            PrepareStatus status = found.get(path);
            out.add(status != null ? status : PrepareStatus.unanswered(path));
        }
        return out;
    }

    /**
     * {@code kXR_query} with {@code kXR_Qspace}: {@code oss.*} CGI. A server
     * is free to answer with a subset of the keys, so missing ones keep a
     * default — for the quota that is -1, "no limit", because a zero would
     * read as a pool nobody may write a byte to.
     */
    public static SpaceInfo parseSpace(byte[] data) {
        Map<String, String> fields = new HashMap<>();
        for (String pair : textOf(data).trim().replace("\n", "&").split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                fields.put(pair.substring(0, eq).trim(), pair.substring(eq + 1).trim());
            }
        }
        return new SpaceInfo(fields.getOrDefault("oss.cgroup", ""),
                cgiLong(fields, "oss.space", 0), cgiLong(fields, "oss.free", 0),
                cgiLong(fields, "oss.maxf", 0), cgiLong(fields, "oss.used", 0),
                cgiLong(fields, "oss.quota", -1));
    }

    private static long cgiLong(Map<String, String> fields, String key, long dflt) {
        String raw = fields.get(key);
        if (raw == null || raw.isEmpty()) {
            return dflt;
        }
        try {
            return Long.parseLong(raw);
        } catch (NumberFormatException e) {
            throw new XrdProtocolException("kXR_Qspace " + key + "=" + raw + " is not a number", e);
        }
    }

    // ---------------------------------------------------------------
    // Vector I/O and extended attributes
    // ---------------------------------------------------------------

    /** {@code kXR_readv}: repeated readahead_list headers each followed by data. */
    public static List<ReadVSegment> parseReadV(byte[] data) {
        RBuf r = new RBuf(data, "kXR_readv");
        List<ReadVSegment> out = new ArrayList<>();
        while (r.remaining() > 0) {
            byte[] fhandle = r.bytes(XrdConst.FHANDLE_LEN);
            int length = r.i32();
            long offset = r.i64();
            if (length < 0) {
                throw new XrdProtocolException(
                        "kXR_readv segment declares a negative length of " + length);
            }
            out.add(new ReadVSegment(fhandle, offset, r.bytes(length)));
        }
        return out;
    }

    /** {@code kXR_fattr}: {@code nerrs[1] nattr[1]} then
     *  {@code rc[2] name\0 [len[4] value]} per attribute. */
    public static FattrResult parseFattr(byte[] data, boolean withValues) {
        if (data.length < 2) {
            return new FattrResult(0, List.of());
        }
        RBuf r = new RBuf(data, "kXR_fattr");
        int errors = r.u8();
        int count = r.u8();
        List<FattrItem> items = new ArrayList<>();
        for (int i = 0; i < count && r.remaining() >= 3; i++) {
            int code = r.u16();
            String name = r.cstring();
            byte[] value = null;
            if (withValues && r.remaining() >= 4) {
                value = r.bytes(r.i32());
            }
            items.add(new FattrItem(name, code, value));
        }
        return new FattrResult(errors, List.copyOf(items));
    }
}

package io.github.robc.jroot.wire;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static io.github.robc.jroot.wire.XrdConst.*;

/**
 * One encoder per {@code kXR_*} opcode. Layouts follow {@code XProtocol.hh},
 * cross-checked against go-hep {@code xrootd/xrdproto} and PyXRootDClient
 * {@code proto/requests.py}. Every {@code params} writes exactly 16 bytes.
 */
public final class Requests {

    private Requests() {}

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    // ---------------------------------------------------------------
    // Session bring-up
    // ---------------------------------------------------------------

    /** {@code kXR_protocol} — capability negotiation. */
    public static final class Protocol extends XrdRequest {
        private final int flags;

        public Protocol(int flags) {
            this.flags = flags;
        }

        @Override public int opcode() { return kXR_protocol; }

        @Override protected void params(WBuf w) {
            w.i32(kXR_PROTOCOLVERSION).u8(flags).u8(kXR_ExpLogin).zeros(10);
        }
    }

    /** {@code kXR_login}. */
    public static final class Login extends XrdRequest {
        private final String username;
        private final int pid;
        private final String token;

        public Login(String username, int pid, String token) {
            this.username = username;
            this.pid = pid;
            this.token = token;
        }

        @Override public int opcode() { return kXR_login; }

        @Override protected void params(WBuf w) {
            // pid[4] username[8] reserved[1] ability[1] capver[1] role[1]
            w.i32(pid).padded(username, 8).zeros(2).u8(kXR_ver005 | kXR_asyncap).u8(0);
        }

        @Override protected byte[] payload() {
            return utf8(token);
        }
    }

    /** {@code kXR_auth} — one round of a credential exchange. */
    public static final class Auth extends XrdRequest {
        private final String credtype;
        private final byte[] cred;

        public Auth(String credtype, byte[] cred) {
            if (utf8(credtype).length > 4) {
                throw new IllegalArgumentException("credtype must be <= 4 bytes: " + credtype);
            }
            this.credtype = credtype;
            this.cred = cred;
        }

        @Override public int opcode() { return kXR_auth; }

        @Override protected void params(WBuf w) {
            w.zeros(12).padded(credtype, 4);
        }

        @Override protected byte[] payload() {
            return cred;
        }
    }

    /** {@code kXR_ping}. */
    public static final class Ping extends XrdRequest {
        @Override public int opcode() { return kXR_ping; }
    }

    /** {@code kXR_endsess} — graceful session teardown. */
    public static final class EndSession extends XrdRequest {
        private final byte[] sessionId;

        public EndSession(byte[] sessionId) {
            this.sessionId = sessionId;
        }

        @Override public int opcode() { return kXR_endsess; }

        @Override protected void params(WBuf w) {
            w.padded(sessionId, 16);
        }
    }

    /** {@code kXR_bind} — attach an extra data connection to a session. */
    public static final class Bind extends XrdRequest {
        private final byte[] sessionId;

        public Bind(byte[] sessionId) {
            this.sessionId = sessionId;
        }

        @Override public int opcode() { return kXR_bind; }

        @Override protected void params(WBuf w) {
            w.padded(sessionId, 16);
        }
    }

    // ---------------------------------------------------------------
    // Metadata
    // ---------------------------------------------------------------

    /** {@code kXR_stat} — by path, or by handle when {@code fhandle} is set. */
    public static final class Stat extends XrdRequest {
        private final String path;
        private final int options;
        private final byte[] fhandle;

        public Stat(String path, int options, byte[] fhandle) {
            this.path = path;
            this.options = options;
            this.fhandle = fhandle;
        }

        public Stat(String path) {
            this(path, 0, NULL_FHANDLE);
        }

        @Override public int opcode() { return kXR_stat; }

        @Override protected void params(WBuf w) {
            w.u8(options).zeros(11).padded(fhandle, 4);
        }

        @Override protected byte[] payload() {
            return utf8(path);
        }
    }

    /** {@code kXR_statx} — flag-only stat of many paths at once. */
    public static final class Statx extends XrdRequest {
        private final List<String> paths;

        public Statx(List<String> paths) {
            this.paths = List.copyOf(paths);
        }

        @Override public int opcode() { return kXR_statx; }

        @Override protected byte[] payload() {
            return utf8(String.join("\n", paths));
        }
    }

    /** {@code kXR_dirlist}. */
    public static final class Dirlist extends XrdRequest {
        private final String path;
        private final int options;

        public Dirlist(String path, int options) {
            this.path = path;
            this.options = options;
        }

        @Override public int opcode() { return kXR_dirlist; }

        @Override protected void params(WBuf w) {
            w.zeros(15).u8(options);
        }

        @Override protected byte[] payload() {
            return utf8(path);
        }
    }

    /** {@code kXR_locate}. */
    public static final class Locate extends XrdRequest {
        private final String path;
        private final int options;

        public Locate(String path, int options) {
            this.path = path;
            this.options = options;
        }

        @Override public int opcode() { return kXR_locate; }

        @Override protected void params(WBuf w) {
            w.u16(options).zeros(14);
        }

        @Override protected byte[] payload() {
            return utf8(path);
        }
    }

    /** {@code kXR_query}. */
    public static final class Query extends XrdRequest {
        private final int infotype;
        private final byte[] args;
        private final byte[] fhandle;

        public Query(int infotype, byte[] args, byte[] fhandle) {
            this.infotype = infotype;
            this.args = args;
            this.fhandle = fhandle;
        }

        public Query(int infotype, String args) {
            this(infotype, utf8(args), NULL_FHANDLE);
        }

        @Override public int opcode() { return kXR_query; }

        @Override protected void params(WBuf w) {
            w.u16(infotype).zeros(2).padded(fhandle, 4).zeros(8);
        }

        @Override protected byte[] payload() {
            return args;
        }
    }

    /** {@code kXR_prepare} — stage or evict files. */
    public static final class Prepare extends XrdRequest {
        private final List<String> paths;
        private final int options;
        private final int priority;
        private final int port;
        private final int optionX;

        public Prepare(List<String> paths, int options, int priority, int port, int optionX) {
            this.paths = List.copyOf(paths);
            this.options = options;
            this.priority = priority;
            this.port = port;
            this.optionX = optionX;
        }

        @Override public int opcode() { return kXR_prepare; }

        @Override public boolean signed() { return true; }

        @Override protected void params(WBuf w) {
            w.u8(options).u8(priority).u16(port).u16(optionX).zeros(10);
        }

        @Override protected byte[] payload() {
            return utf8(String.join("\n", paths));
        }
    }

    // ---------------------------------------------------------------
    // Namespace mutation
    // ---------------------------------------------------------------

    /** {@code kXR_mkdir}. */
    public static final class Mkdir extends XrdRequest {
        private final String path;
        private final int mode;
        private final boolean makePath;

        public Mkdir(String path, int mode, boolean makePath) {
            this.path = path;
            this.mode = mode;
            this.makePath = makePath;
        }

        @Override public int opcode() { return kXR_mkdir; }

        @Override public boolean signed() { return true; }

        @Override protected void params(WBuf w) {
            w.u8(makePath ? kXR_mkdirpath : 0).zeros(13).u16(mode);
        }

        @Override protected byte[] payload() {
            return utf8(path);
        }
    }

    /** {@code kXR_rm}. */
    public static class Rm extends XrdRequest {
        private final String path;

        public Rm(String path) {
            this.path = path;
        }

        @Override public int opcode() { return kXR_rm; }

        @Override public boolean signed() { return true; }

        @Override protected byte[] payload() {
            return utf8(path);
        }
    }

    /** {@code kXR_rmdir}. */
    public static final class Rmdir extends Rm {
        public Rmdir(String path) {
            super(path);
        }

        @Override public int opcode() { return kXR_rmdir; }
    }

    /** {@code kXR_mv} — the payload is {@code "<src> <dst>"}, split by arg1len. */
    public static final class Mv extends XrdRequest {
        private final String src;
        private final String dst;

        public Mv(String src, String dst) {
            this.src = src;
            this.dst = dst;
        }

        @Override public int opcode() { return kXR_mv; }

        @Override public boolean signed() { return true; }

        @Override protected void params(WBuf w) {
            w.zeros(14).u16(utf8(src).length);
        }

        @Override protected byte[] payload() {
            return utf8(src + " " + dst);
        }
    }

    /** {@code kXR_chmod}. */
    public static final class Chmod extends XrdRequest {
        private final String path;
        private final int mode;

        public Chmod(String path, int mode) {
            this.path = path;
            this.mode = mode;
        }

        @Override public int opcode() { return kXR_chmod; }

        @Override public boolean signed() { return true; }

        @Override protected void params(WBuf w) {
            w.zeros(14).u16(mode);
        }

        @Override protected byte[] payload() {
            return utf8(path);
        }
    }

    /** {@code kXR_truncate} — by path, or by handle when {@code fhandle} is set. */
    public static final class Truncate extends XrdRequest {
        private final String path;
        private final long size;
        private final byte[] fhandle;

        public Truncate(String path, long size, byte[] fhandle) {
            this.path = path;
            this.size = size;
            this.fhandle = fhandle;
        }

        @Override public int opcode() { return kXR_truncate; }

        @Override public boolean signed() { return true; }

        @Override protected void params(WBuf w) {
            w.padded(fhandle, 4).i64(size).zeros(4);
        }

        @Override protected byte[] payload() {
            return utf8(path);
        }
    }

    // ---------------------------------------------------------------
    // File I/O
    // ---------------------------------------------------------------

    /** {@code kXR_open}. */
    public static final class Open extends XrdRequest {
        private final String path;
        private final int options;
        private final int mode;

        public Open(String path, int options, int mode) {
            this.path = path;
            this.options = options;
            this.mode = mode;
        }

        @Override public int opcode() { return kXR_open; }

        @Override public boolean signed() { return true; }

        @Override protected void params(WBuf w) {
            w.u16(mode).u16(options).zeros(12);
        }

        @Override protected byte[] payload() {
            return utf8(path);
        }
    }

    /** {@code kXR_close}. */
    public static final class Close extends XrdRequest {
        private final byte[] fhandle;

        public Close(byte[] fhandle) {
            this.fhandle = fhandle;
        }

        @Override public int opcode() { return kXR_close; }

        @Override protected void params(WBuf w) {
            w.padded(fhandle, 4).zeros(12);
        }
    }

    /** {@code kXR_read}. */
    public static final class Read extends XrdRequest {
        private final byte[] fhandle;
        private final long offset;
        private final int length;

        public Read(byte[] fhandle, long offset, int length) {
            this.fhandle = fhandle;
            this.offset = offset;
            this.length = length;
        }

        @Override public int opcode() { return kXR_read; }

        @Override protected void params(WBuf w) {
            w.padded(fhandle, 4).i64(offset).i32(length);
        }
    }

    /** {@code kXR_write}. */
    public static final class Write extends XrdRequest {
        private final byte[] fhandle;
        private final long offset;
        private final byte[] data;

        public Write(byte[] fhandle, long offset, byte[] data) {
            this.fhandle = fhandle;
            this.offset = offset;
            this.data = data;
        }

        @Override public int opcode() { return kXR_write; }

        @Override public boolean signed() { return true; }

        @Override protected void params(WBuf w) {
            w.padded(fhandle, 4).i64(offset).zeros(4);
        }

        @Override protected byte[] payload() {
            return data;
        }
    }

    /** {@code kXR_sync}. */
    public static final class Sync extends XrdRequest {
        private final byte[] fhandle;

        public Sync(byte[] fhandle) {
            this.fhandle = fhandle;
        }

        @Override public int opcode() { return kXR_sync; }

        @Override protected void params(WBuf w) {
            w.padded(fhandle, 4).zeros(12);
        }
    }

    /** One scattered range of a {@code kXR_readv}/{@code kXR_writev}. */
    public record Segment(byte[] fhandle, long offset, int length) {}

    /** {@code kXR_readv} — many scattered ranges in one round trip. */
    public static final class ReadV extends XrdRequest {
        private final List<Segment> segments;

        public ReadV(List<Segment> segments) {
            if (segments.size() > VEC_MAXSEGS) {
                throw new IllegalArgumentException(
                        segments.size() + " segments exceeds the readv cap of " + VEC_MAXSEGS);
            }
            this.segments = List.copyOf(segments);
        }

        @Override public int opcode() { return kXR_readv; }

        @Override protected byte[] payload() {
            // readahead_list: fhandle[4] rlen[4] roffset[8], per segment.
            WBuf w = new WBuf();
            for (Segment s : segments) {
                w.padded(s.fhandle(), 4).i32(s.length()).i64(s.offset());
            }
            return w.bytes();
        }
    }

    /** One range of a {@code kXR_writev}: where {@code data} lands. */
    public record WriteSegment(byte[] fhandle, long offset, byte[] data) {}

    /**
     * {@code kXR_writev}. {@code dlen} covers the descriptor block
     * (fhandle[4] wlen[4] offset[8] each) and nothing else; the concatenated
     * data streams after the frame as a trailer.
     */
    public static final class WriteV extends XrdRequest {
        private final List<WriteSegment> segments;
        private final boolean sync;

        public WriteV(List<WriteSegment> segments, boolean sync) {
            this.segments = List.copyOf(segments);
            this.sync = sync;
        }

        @Override public int opcode() { return kXR_writev; }

        @Override public boolean signed() { return true; }

        @Override protected void params(WBuf w) {
            w.u8(sync ? kXR_wv_doSync : 0).zeros(15);
        }

        @Override protected byte[] payload() {
            WBuf w = new WBuf();
            for (WriteSegment s : segments) {
                w.padded(s.fhandle(), 4).i32(s.data().length).i64(s.offset());
            }
            return w.bytes();
        }

        @Override protected byte[] trailer() {
            WBuf w = new WBuf();
            for (WriteSegment s : segments) {
                w.raw(s.data());
            }
            return w.bytes();
        }
    }

    /** {@code kXR_pgread} — read with a per-4KiB-page CRC32c. */
    public static final class PgRead extends XrdRequest {
        private final byte[] fhandle;
        private final long offset;
        private final int length;

        public PgRead(byte[] fhandle, long offset, int length) {
            this.fhandle = fhandle;
            this.offset = offset;
            this.length = length;
        }

        @Override public int opcode() { return kXR_pgread; }

        @Override protected void params(WBuf w) {
            w.padded(fhandle, 4).i64(offset).i32(length);
        }
    }

    /** {@code kXR_pgwrite} — the payload is already CRC-interleaved
     *  ({@link PagedIo#packPages}). */
    public static final class PgWrite extends XrdRequest {
        private final byte[] fhandle;
        private final long offset;
        private final byte[] packed;

        public PgWrite(byte[] fhandle, long offset, byte[] packed) {
            this.fhandle = fhandle;
            this.offset = offset;
            this.packed = packed;
        }

        @Override public int opcode() { return kXR_pgwrite; }

        @Override public boolean signed() { return true; }

        @Override protected void params(WBuf w) {
            w.padded(fhandle, 4).i64(offset).zeros(4);
        }

        @Override protected byte[] payload() {
            return packed;
        }
    }

    /**
     * {@code kXR_fattr} — extended attributes. The body is
     * {@code path\0} then, per attribute, a 2-byte rc placeholder,
     * {@code name\0}, and for SET a 4-byte length followed by the value.
     */
    public static final class Fattr extends XrdRequest {
        private final int subcode;
        private final int numattr;
        private final int options;
        private final byte[] fhandle;
        private final byte[] body;

        private Fattr(int subcode, byte[] body, int numattr, int options, byte[] fhandle) {
            this.subcode = subcode;
            this.body = body;
            this.numattr = numattr;
            this.options = options;
            this.fhandle = fhandle;
        }

        private static byte[] pathName(String path, String name) {
            return new WBuf().text(path, true).u16(0).text(name, true).bytes();
        }

        public static Fattr get(String path, String name) {
            return new Fattr(kXR_fattrGet, pathName(path, name), 1, 0, NULL_FHANDLE);
        }

        public static Fattr delete(String path, String name) {
            return new Fattr(kXR_fattrDel, pathName(path, name), 1, 0, NULL_FHANDLE);
        }

        public static Fattr set(String path, String name, byte[] value, boolean createOnly) {
            byte[] body = new WBuf().raw(pathName(path, name))
                    .i32(value.length).raw(value).bytes();
            return new Fattr(kXR_fattrSet, body, 1, createOnly ? kXR_fa_isNew : 0, NULL_FHANDLE);
        }

        public static Fattr list(String path, boolean withValues) {
            byte[] body = new WBuf().text(path, true).bytes();
            return new Fattr(kXR_fattrList, body, 0, withValues ? kXR_fa_aData : 0, NULL_FHANDLE);
        }

        @Override public int opcode() { return kXR_fattr; }

        @Override public boolean signed() { return true; }

        @Override protected void params(WBuf w) {
            w.padded(fhandle, 4).u8(subcode).u8(numattr).u8(options).zeros(9);
        }

        @Override protected byte[] payload() {
            return body;
        }
    }

    /**
     * {@code kXR_set} — tell the server something about this client. The
     * payload is one directive: {@code "appid <text>"} names the application
     * in the server's logs, {@code "monitor <what>"} turns monitoring on.
     */
    public static final class Set extends XrdRequest {
        private final String directive;

        public Set(String directive) {
            this.directive = directive;
        }

        /** What shows up beside this client's requests in a server log. */
        public static Set appId(String name) {
            return new Set("appid " + name);
        }

        @Override public int opcode() { return kXR_set; }

        @Override public boolean signed() { return true; }

        @Override protected void params(WBuf w) {
            w.zeros(15).u8(0);              // reserved[15] then the modifier byte
        }

        @Override protected byte[] payload() {
            return utf8(directive);
        }
    }

    /**
     * {@code kXR_chkpoint} — a transaction over one open file.
     *
     * <p>Begin a checkpoint, run writes and truncates through
     * {@link #exec}, and either commit them or roll the file back to what it
     * held when the checkpoint opened. A server keeps the undo data itself,
     * which is why the request that is undone travels inside this one as a
     * complete frame rather than being sent on its own.
     */
    public static final class Chkpoint extends XrdRequest {
        private final byte[] fhandle;
        private final int subcode;
        private final byte[] body;

        private Chkpoint(byte[] fhandle, int subcode, byte[] body) {
            this.fhandle = fhandle;
            this.subcode = subcode;
            this.body = body;
        }

        public static Chkpoint begin(byte[] fhandle) {
            return new Chkpoint(fhandle, kXR_ckpBegin, new byte[0]);
        }

        public static Chkpoint commit(byte[] fhandle) {
            return new Chkpoint(fhandle, kXR_ckpCommit, new byte[0]);
        }

        /** How much checkpoint space the server will still allow. */
        public static Chkpoint query(byte[] fhandle) {
            return new Chkpoint(fhandle, kXR_ckpQuery, new byte[0]);
        }

        public static Chkpoint rollback(byte[] fhandle) {
            return new Chkpoint(fhandle, kXR_ckpRollback, new byte[0]);
        }

        /**
         * Run {@code request} — a write, pgwrite or truncate — inside the
         * checkpoint. It is carried as the frame it would have been on its
         * own, with stream id zero: the server replies to the checkpoint,
         * not to the request inside it.
         */
        public static Chkpoint exec(byte[] fhandle, XrdRequest request) {
            int opcode = request.opcode();
            if (opcode != kXR_write && opcode != kXR_pgwrite && opcode != kXR_truncate) {
                throw new IllegalArgumentException(
                        "a checkpoint can only carry write, pgwrite or truncate, not "
                                + XrdConst.requestName(opcode));
            }
            return new Chkpoint(fhandle, kXR_ckpXeq, request.encode(0));
        }

        @Override public int opcode() { return kXR_chkpoint; }

        @Override public boolean signed() { return true; }

        @Override protected void params(WBuf w) {
            w.padded(fhandle, 4).zeros(11).u8(subcode);
        }

        @Override protected byte[] payload() {
            return body;
        }
    }

    /** {@code kXR_sigver} — the signature frame that prefixes a signed request. */
    public static final class Sigver extends XrdRequest {
        private final int expectrid;
        private final long seqno;
        private final byte[] signature;
        private final boolean nodata;

        public Sigver(int expectrid, long seqno, byte[] signature, boolean nodata) {
            this.expectrid = expectrid;
            this.seqno = seqno;
            this.signature = signature;
            this.nodata = nodata;
        }

        @Override public int opcode() { return kXR_sigver; }

        @Override protected void params(WBuf w) {
            w.u16(expectrid).u8(0).u8(nodata ? kXR_nodata_sig : 0)
                    .i64(seqno).u8(kXR_SHA256_sig).zeros(3);
        }

        @Override protected byte[] payload() {
            return signature;
        }
    }
}

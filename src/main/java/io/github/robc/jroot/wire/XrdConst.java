package io.github.robc.jroot.wire;

import java.util.Map;

/**
 * XRootD protocol constants. Names follow the protocol vocabulary
 * ({@code XProtocol.hh}) so every value is greppable against the C++
 * reference; this deliberately departs from Java naming style.
 */
public final class XrdConst {

    private XrdConst() {}

    // ---- request opcodes (ClientRequestHdr.requestid) ----
    public static final int kXR_auth     = 3000;
    public static final int kXR_query    = 3001;
    public static final int kXR_chmod    = 3002;
    public static final int kXR_close    = 3003;
    public static final int kXR_dirlist  = 3004;
    public static final int kXR_gpfile   = 3005;
    public static final int kXR_protocol = 3006;
    public static final int kXR_login    = 3007;
    public static final int kXR_mkdir    = 3008;
    public static final int kXR_mv       = 3009;
    public static final int kXR_open     = 3010;
    public static final int kXR_ping     = 3011;
    public static final int kXR_chkpoint = 3012;
    public static final int kXR_read     = 3013;
    public static final int kXR_rm       = 3014;
    public static final int kXR_rmdir    = 3015;
    public static final int kXR_sync     = 3016;
    public static final int kXR_stat     = 3017;
    public static final int kXR_set      = 3018;
    public static final int kXR_write    = 3019;
    public static final int kXR_fattr    = 3020;
    public static final int kXR_prepare  = 3021;
    public static final int kXR_statx    = 3022;
    public static final int kXR_endsess  = 3023;
    public static final int kXR_bind     = 3024;
    public static final int kXR_readv    = 3025;
    public static final int kXR_pgwrite  = 3026;
    public static final int kXR_locate   = 3027;
    public static final int kXR_truncate = 3028;
    public static final int kXR_sigver   = 3029;
    public static final int kXR_pgread   = 3030;
    public static final int kXR_writev   = 3031;
    public static final int kXR_clone    = 3032;
    /** The lowest request opcode; kXR_status reqid bytes and security
     *  overrides are offsets from it. */
    public static final int kXR_1stRequest = kXR_auth;

    // ---- response status (ServerResponseHdr.status) ----
    public static final int kXR_ok       = 0;
    public static final int kXR_oksofar  = 4000;
    public static final int kXR_attn     = 4001;
    public static final int kXR_authmore = 4002;
    public static final int kXR_error    = 4003;
    public static final int kXR_redirect = 4004;
    public static final int kXR_wait     = 4005;
    public static final int kXR_waitresp = 4006;
    public static final int kXR_status   = 4007;

    // ---- server error codes (XErrorCode). Distinct from POSIX errno, and
    // sharing their numeric range with the request opcodes without being
    // related to them: 3011 is kXR_ping as a request and kXR_NotFound as an
    // error. ----
    public static final int kXR_ArgInvalid     = 3000;
    public static final int kXR_ArgMissing     = 3001;
    public static final int kXR_ArgTooLong     = 3002;
    public static final int kXR_FileLocked     = 3003;
    public static final int kXR_FileNotOpen    = 3004;
    public static final int kXR_FSError        = 3005;
    public static final int kXR_InvalidRequest = 3006;
    public static final int kXR_IOError        = 3007;
    public static final int kXR_NoMemory       = 3008;
    public static final int kXR_NoSpace        = 3009;
    public static final int kXR_NotAuthorized  = 3010;
    public static final int kXR_NotFound       = 3011;
    public static final int kXR_ServerError    = 3012;
    public static final int kXR_Unsupported    = 3013;
    public static final int kXR_noserver       = 3014;
    public static final int kXR_NotFile        = 3015;
    public static final int kXR_isDirectory    = 3016;
    public static final int kXR_Cancelled      = 3017;
    public static final int kXR_ItExists       = 3018;
    public static final int kXR_ChkSumErr      = 3019;
    public static final int kXR_inProgress     = 3020;
    public static final int kXR_overQuota      = 3021;
    public static final int kXR_SigVerErr      = 3022;
    public static final int kXR_DecryptErr     = 3023;
    public static final int kXR_Overloaded     = 3024;
    public static final int kXR_fsReadOnly     = 3025;
    public static final int kXR_BadPayload     = 3026;
    public static final int kXR_AttrNotFound   = 3027;
    public static final int kXR_TLSRequired    = 3028;
    public static final int kXR_noReplicas     = 3029;
    public static final int kXR_AuthFailed     = 3030;
    public static final int kXR_Impossible     = 3031;
    public static final int kXR_Conflict       = 3032;
    public static final int kXR_TooManyErrs    = 3033;

    // ---- kXR_attn action codes (still-active subset) ----
    public static final int kXR_asyncms  = 5002;
    public static final int kXR_asynresp = 5008;

    // ---- kXR_protocol response flags (server type + TLS negotiation) ----
    public static final int kXR_isServer  = 0x00000001;
    public static final int kXR_isManager = 0x00000002;
    public static final int kXR_attrMeta  = 0x00000100;
    public static final int kXR_attrProxy = 0x00000200;
    public static final int kXR_attrSuper = 0x00000400;

    public static final int kXR_haveTLS  = 0x80000000; // server accepts in-protocol TLS upgrade
    public static final int kXR_gotoTLS  = 0x40000000; // client must upgrade immediately
    public static final int kXR_tlsGPFA  = 0x20000000; // anonymous gpfile requires TLS
    public static final int kXR_tlsTPC   = 0x10000000; // third-party copy must run over TLS
    public static final int kXR_tlsSess  = 0x08000000; // the session after login requires TLS
    public static final int kXR_tlsLogin = 0x04000000; // the login exchange requires TLS
    public static final int kXR_tlsGPF   = 0x02000000; // gpfile requests require TLS
    public static final int kXR_tlsData  = 0x01000000; // file data must move over TLS

    // Capabilities the server volunteers in the same word.
    public static final int kXR_anongpf = 0x00800000;
    public static final int kXR_supgpf  = 0x00400000;
    public static final int kXR_suppgrw = 0x00200000;
    public static final int kXR_supposc = 0x00100000;

    // ---- handshake / kXR_protocol ----
    /** Fifth word of the 20-byte client hello. */
    public static final int ROOTD_PQ = 2012;
    /** Protocol version this client speaks: 5.2.0. */
    public static final int kXR_PROTOCOLVERSION = 0x00000520;
    public static final int kXR_secreqs  = 0x01; // request the security-protocol trailer
    public static final int kXR_ableTLS  = 0x02; // client can upgrade to in-protocol TLS
    public static final int kXR_wantTLS  = 0x04; // client requires TLS - abort if unavailable
    public static final int kXR_ExpLogin = 0x03; // "a kXR_login follows"

    // ---- what the handshake reply says the server is ----
    public static final int kXR_DataServer = 1; // holds files; open and read here
    public static final int kXR_LBalServer = 0; // a manager; expect a redirect

    // ---- kXR_login capver ----
    public static final int kXR_asyncap = 0x80; // client handles asynchronous responses
    public static final int kXR_ver005  = 0x05; // XRootD v5 client (TLS + sigver capable)

    /** Opaque sessid bytes in the login response. */
    public static final int SESSION_ID_LEN = 16;
    public static final int FHANDLE_LEN = 4;
    public static final byte[] NULL_FHANDLE = new byte[4];

    public static final int REQUEST_HDRLEN = 24;
    public static final int RESPONSE_HDRLEN = 8;

    // ---- kXR_dirlist options ----
    public static final int kXR_online = 0x01;
    public static final int kXR_dstat  = 0x02;
    public static final int kXR_dcksm  = 0x04;

    // ---- kXR_stat options ----
    public static final int kXR_vfs          = 0x01;
    public static final int kXR_statNoFollow = 0x02;

    // ---- kXR_open options ----
    public static final int kXR_compress  = 0x0001;
    public static final int kXR_delete    = 0x0002;
    public static final int kXR_force     = 0x0004;
    public static final int kXR_new       = 0x0008;
    public static final int kXR_open_read = 0x0010;
    public static final int kXR_open_updt = 0x0020;
    public static final int kXR_async     = 0x0040;
    public static final int kXR_refresh   = 0x0080;
    public static final int kXR_mkpath    = 0x0100;
    public static final int kXR_open_apnd = 0x0200;
    public static final int kXR_retstat   = 0x0400;
    public static final int kXR_replica   = 0x0800;
    public static final int kXR_posc      = 0x1000;
    public static final int kXR_nowait    = 0x2000;
    public static final int kXR_seqio     = 0x4000;
    public static final int kXR_open_wrto = 0x8000;

    // ---- kXR_mkdir options byte ----
    public static final int kXR_mkdirpath = 0x01;

    // ---- access modes, for kXR_mkdir, kXR_open and kXR_chmod ----
    // The protocol's bits sit exactly where the POSIX permission bits do, so
    // an octal literal such as 0755 means on the wire what it means in a shell.
    public static final int kXR_ur = 0x100;
    public static final int kXR_uw = 0x080;
    public static final int kXR_ux = 0x040;
    public static final int kXR_gr = 0x020;
    public static final int kXR_gw = 0x010;
    public static final int kXR_gx = 0x008;
    public static final int kXR_or = 0x004;
    public static final int kXR_ow = 0x002;
    public static final int kXR_ox = 0x001;
    /** 0755: what a directory gets when the caller does not say. */
    public static final int DEFAULT_DIR_MODE = 0755;
    /** 0644: what a new file gets when the caller does not say. */
    public static final int DEFAULT_FILE_MODE = 0644;

    // ---- kXR_query infotype ----
    public static final int kXR_QStats  = 1;
    public static final int kXR_QPrep   = 2;
    public static final int kXR_Qcksum  = 3;
    public static final int kXR_Qxattr  = 4;
    public static final int kXR_Qspace  = 5;
    public static final int kXR_Qckscan = 6;
    public static final int kXR_Qconfig = 7;
    public static final int kXR_Qvisa   = 8;
    public static final int kXR_Qopaque = 16;
    public static final int kXR_Qopaquf = 32;
    public static final int kXR_Qopaqug = 64;

    // ---- kXR_locate options ----
    public static final int kXR_addPeers   = 0x0001;
    public static final int kXR_refreshLoc = 0x0080;
    public static final int kXR_prefname   = 0x0100;
    public static final int kXR_nowaitLoc  = 0x2000;

    // ---- kXR_prepare options ----
    public static final int kXR_cancel = 0x01;
    public static final int kXR_notify = 0x02;
    public static final int kXR_noerrs = 0x04;
    public static final int kXR_stage  = 0x08;
    public static final int kXR_wmode  = 0x10;
    public static final int kXR_coloc  = 0x20;
    public static final int kXR_fresh  = 0x40;
    public static final int kXR_usetcp = 0x80;
    /** Modifier for the optionX half-word, not the options byte. */
    public static final int kXR_evict  = 0x0001;

    // ---- kXR_writev options ----
    public static final int kXR_wv_doSync = 0x01;

    // ---- kXR_fattr subcodes + options ----
    public static final int kXR_fattrDel  = 0x00;
    public static final int kXR_fattrGet  = 0x01;
    public static final int kXR_fattrList = 0x02;
    public static final int kXR_fattrSet  = 0x03;
    public static final int kXR_fa_isNew  = 0x01;
    public static final int kXR_fa_aData  = 0x10;
    public static final int kXR_fattrMaxVars = 16;

    // ---- kXR_chkpoint subcodes ----
    public static final int kXR_ckpBegin    = 0x00;
    public static final int kXR_ckpCommit   = 0x01;
    public static final int kXR_ckpQuery    = 0x02;
    public static final int kXR_ckpRollback = 0x03;
    public static final int kXR_ckpXeq      = 0x04;

    // ---- kXR_sigver ----
    public static final int kXR_SHA256_sig = 0x01; // signature hash is SHA-256 (secver 0)
    public static final int kXR_nodata_sig = 0x01; // payload NOT included in the hash

    // ---- security levels (kXR_protocol trailer) ----
    public static final int kXR_secNone       = 0;
    public static final int kXR_secCompatible = 1;
    public static final int kXR_secStandard   = 2;
    public static final int kXR_secIntense    = 3;
    public static final int kXR_secPedantic   = 4;
    // secopt bits
    public static final int kXR_secOData = 0x01; // sign data payloads too
    public static final int kXR_secOFrce = 0x02; // sign even when encrypted
    // per-request overrides in the trailer's secvec entries
    public static final int kXR_signIgnore = 0x00;
    public static final int kXR_signLikely = 0x01;
    public static final int kXR_signNeeded = 0x02;

    // ---- paged I/O ----
    public static final int kXR_pgPageSZ = 4096; // page size; CRC32c per page
    public static final int kXR_pgRetry  = 0x01;
    public static final int kXR_FinalResult   = 0x00; // kXR_status resptype: last frame
    public static final int kXR_PartialResult = 0x01; // more frames follow

    // ---- kXR_stat flags bitfield ----
    public static final int kXR_file     = 0x00;
    public static final int kXR_xset     = 0x01;
    public static final int kXR_isDir    = 0x02;
    public static final int kXR_other    = 0x04;
    public static final int kXR_offline  = 0x08;
    public static final int kXR_readable = 0x10;
    public static final int kXR_writable = 0x20;
    public static final int kXR_poscpend = 0x40;
    public static final int kXR_bkpexist = 0x80;

    // ---- client-side caps. A response is untrusted input: every accumulating
    // read bounds what it will buffer, so a server that keeps sending
    // kXR_oksofar cannot grow the client's heap without limit. ----
    public static final int MAX_RESPONSE_BODY = 64 * 1024 * 1024;
    public static final int VEC_MAXSEGS = 1024;
    public static final int DEFAULT_PORT = 1094;

    private static final Map<Integer, String> REQUEST_NAMES = Map.ofEntries(
            Map.entry(kXR_auth, "kXR_auth"), Map.entry(kXR_query, "kXR_query"),
            Map.entry(kXR_chmod, "kXR_chmod"), Map.entry(kXR_close, "kXR_close"),
            Map.entry(kXR_dirlist, "kXR_dirlist"), Map.entry(kXR_gpfile, "kXR_gpfile"),
            Map.entry(kXR_protocol, "kXR_protocol"), Map.entry(kXR_login, "kXR_login"),
            Map.entry(kXR_mkdir, "kXR_mkdir"), Map.entry(kXR_mv, "kXR_mv"),
            Map.entry(kXR_open, "kXR_open"), Map.entry(kXR_ping, "kXR_ping"),
            Map.entry(kXR_chkpoint, "kXR_chkpoint"), Map.entry(kXR_read, "kXR_read"),
            Map.entry(kXR_rm, "kXR_rm"), Map.entry(kXR_rmdir, "kXR_rmdir"),
            Map.entry(kXR_sync, "kXR_sync"), Map.entry(kXR_stat, "kXR_stat"),
            Map.entry(kXR_set, "kXR_set"), Map.entry(kXR_write, "kXR_write"),
            Map.entry(kXR_fattr, "kXR_fattr"), Map.entry(kXR_prepare, "kXR_prepare"),
            Map.entry(kXR_statx, "kXR_statx"), Map.entry(kXR_endsess, "kXR_endsess"),
            Map.entry(kXR_bind, "kXR_bind"), Map.entry(kXR_readv, "kXR_readv"),
            Map.entry(kXR_pgwrite, "kXR_pgwrite"), Map.entry(kXR_locate, "kXR_locate"),
            Map.entry(kXR_truncate, "kXR_truncate"), Map.entry(kXR_sigver, "kXR_sigver"),
            Map.entry(kXR_pgread, "kXR_pgread"), Map.entry(kXR_writev, "kXR_writev"),
            Map.entry(kXR_clone, "kXR_clone"));

    private static final Map<Integer, String> STATUS_NAMES = Map.of(
            kXR_ok, "kXR_ok", kXR_oksofar, "kXR_oksofar", kXR_attn, "kXR_attn",
            kXR_authmore, "kXR_authmore", kXR_error, "kXR_error",
            kXR_redirect, "kXR_redirect", kXR_wait, "kXR_wait",
            kXR_waitresp, "kXR_waitresp", kXR_status, "kXR_status");

    private static final Map<Integer, String> ERROR_NAMES = Map.ofEntries(
            Map.entry(kXR_ArgInvalid, "kXR_ArgInvalid"), Map.entry(kXR_ArgMissing, "kXR_ArgMissing"),
            Map.entry(kXR_ArgTooLong, "kXR_ArgTooLong"), Map.entry(kXR_FileLocked, "kXR_FileLocked"),
            Map.entry(kXR_FileNotOpen, "kXR_FileNotOpen"), Map.entry(kXR_FSError, "kXR_FSError"),
            Map.entry(kXR_InvalidRequest, "kXR_InvalidRequest"), Map.entry(kXR_IOError, "kXR_IOError"),
            Map.entry(kXR_NoMemory, "kXR_NoMemory"), Map.entry(kXR_NoSpace, "kXR_NoSpace"),
            Map.entry(kXR_NotAuthorized, "kXR_NotAuthorized"), Map.entry(kXR_NotFound, "kXR_NotFound"),
            Map.entry(kXR_ServerError, "kXR_ServerError"), Map.entry(kXR_Unsupported, "kXR_Unsupported"),
            Map.entry(kXR_noserver, "kXR_noserver"), Map.entry(kXR_NotFile, "kXR_NotFile"),
            Map.entry(kXR_isDirectory, "kXR_isDirectory"), Map.entry(kXR_Cancelled, "kXR_Cancelled"),
            Map.entry(kXR_ItExists, "kXR_ItExists"), Map.entry(kXR_ChkSumErr, "kXR_ChkSumErr"),
            Map.entry(kXR_inProgress, "kXR_inProgress"), Map.entry(kXR_overQuota, "kXR_overQuota"),
            Map.entry(kXR_SigVerErr, "kXR_SigVerErr"), Map.entry(kXR_DecryptErr, "kXR_DecryptErr"),
            Map.entry(kXR_Overloaded, "kXR_Overloaded"), Map.entry(kXR_fsReadOnly, "kXR_fsReadOnly"),
            Map.entry(kXR_BadPayload, "kXR_BadPayload"), Map.entry(kXR_AttrNotFound, "kXR_AttrNotFound"),
            Map.entry(kXR_TLSRequired, "kXR_TLSRequired"), Map.entry(kXR_noReplicas, "kXR_noReplicas"),
            Map.entry(kXR_AuthFailed, "kXR_AuthFailed"), Map.entry(kXR_Impossible, "kXR_Impossible"),
            Map.entry(kXR_Conflict, "kXR_Conflict"), Map.entry(kXR_TooManyErrs, "kXR_TooManyErrs"));

    /** The protocol name of a request opcode (3017 → "kXR_stat"), for traces. */
    public static String requestName(int id) {
        String name = REQUEST_NAMES.get(id);
        return name != null ? name : "kXR_unknown(" + id + ")";
    }

    /** The protocol name of a response status (4004 → "kXR_redirect"). */
    public static String statusName(int status) {
        String name = STATUS_NAMES.get(status);
        return name != null ? name : "kXR_status(" + status + ")";
    }

    /**
     * The protocol name of a server error code (3011 → "kXR_NotFound").
     * Not interchangeable with {@link #requestName}: the two enumerations
     * overlap numerically without overlapping in meaning.
     */
    public static String errorName(int code) {
        String name = ERROR_NAMES.get(code);
        return name != null ? name : "kXR_error(" + code + ")";
    }
}

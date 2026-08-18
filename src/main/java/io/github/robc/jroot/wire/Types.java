package io.github.robc.jroot.wire;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/** The value objects a response decodes into. */
public final class Types {

    private Types() {}

    /** A {@code kXR_stat} line: id, size, flags bitfield, mtime (epoch seconds). */
    public record StatInfo(String id, long size, int flags, long mtime, String path) {

        public boolean isDirectory() {
            return (flags & XrdConst.kXR_isDir) != 0;
        }

        public boolean isOffline() {
            return (flags & XrdConst.kXR_offline) != 0;
        }

        public boolean isReadable() {
            return (flags & XrdConst.kXR_readable) != 0;
        }

        public boolean isWritable() {
            return (flags & XrdConst.kXR_writable) != 0;
        }
    }

    /** {@code kXR_stat} with {@code kXR_vfs}: filesystem space, in megabytes. */
    public record VfsInfo(long nodesRw, long freeRw, int utilizationRw,
                          long nodesStaging, long freeStaging, int utilizationStaging) {}

    /** One entry of a {@code kXR_dirlist} reply. */
    public record DirEntry(String name, String parent, Optional<StatInfo> stat) {

        public boolean isDirectory() {
            return stat.map(StatInfo::isDirectory).orElse(false);
        }
    }

    /** One {@code kXR_locate} token: {@code XY<host:port>} — X the server type
     *  (S server, M manager; lower case when pending), Y the access mode. */
    public record LocationInfo(String address, char type, char access) {

        public boolean isServer() {
            return type == 'S' || type == 's';
        }

        public boolean isManager() {
            return type == 'M' || type == 'm';
        }

        public boolean isWritable() {
            return access == 'w';
        }
    }

    /** {@code kXR_protocol}: version, flags, and the security requirements
     *  the {@code kXR_secreqs} trailer carried (defaults when absent). */
    public record ProtocolInfo(int version, int flags, int securityLevel,
                               int securityVersion, int securityOptions,
                               Map<Integer, Integer> securityOverrides) {

        public static final ProtocolInfo NONE =
                new ProtocolInfo(0, 0, XrdConst.kXR_secNone, 0, 0, Map.of());

        public boolean hasTls() {
            return (flags & XrdConst.kXR_haveTLS) != 0;
        }

        /**
         * Whether the server obliges this client to upgrade during bring-up.
         * {@code kXR_tlsData} counts: this client reads and writes on the
         * connection it logged in on, so a server that wants file data
         * encrypted wants this socket encrypted.
         */
        public boolean demandsTls() {
            return (flags & (XrdConst.kXR_gotoTLS | XrdConst.kXR_tlsLogin
                    | XrdConst.kXR_tlsSess | XrdConst.kXR_tlsData)) != 0;
        }
    }

    /** {@code kXR_login}: the session id plus the security continuation. */
    public record LoginInfo(byte[] sessionId, String sec) {

        /** Protocol names offered by the server, most preferred first. */
        public List<String> mechanisms() {
            return sec.isEmpty() ? List.of()
                    : java.util.Arrays.stream(sec.split("&"))
                            .filter(p -> p.startsWith("P="))
                            .map(p -> p.substring(2).split(",", 2)[0])
                            .toList();
        }
    }

    /** {@code kXR_redirect}: where to re-issue the request. A negative port
     *  means the target requires TLS ({@code roots://}). */
    public record RedirectInfo(String host, int port, String opaque) {

        public boolean requiresTls() {
            return port < 0;
        }

        public int actualPort() {
            int p = Math.abs(port);
            return p == 0 ? XrdConst.DEFAULT_PORT : p;
        }
    }

    /** {@code kXR_wait}/{@code kXR_waitresp}: seconds to hold off. */
    public record WaitInfo(int seconds, String message) {}

    /** An unsolicited {@code kXR_attn} that was not an embedded response. */
    public record AttnInfo(int action, byte[] params) {}

    /**
     * Body of a {@code kXR_status} response. {@code crc32c} covers every
     * body byte after itself; {@code dataLength} is the raw data that
     * follows the body on the wire, outside the response header's count.
     */
    public record StatusInfo(long crc32c, int streamId, int requestId,
                             int responseType, int dataLength, byte[] info) {

        public boolean isFinal() {
            return responseType == XrdConst.kXR_FinalResult;
        }
    }

    /** {@code kXR_open}: the handle, the optional {@code kXR_retstat} stat,
     *  and the compression page size/algorithm (0, "" when uncompressed). */
    public record OpenInfo(byte[] fhandle, Optional<StatInfo> stat,
                           int compressionPageSize, String compressionAlgorithm) {}

    /** {@code "<algorithm> <hex value>"} from a checksum query. */
    public record ChecksumInfo(String algorithm, String value) {}

    /** One element of a {@code kXR_readv} response. */
    public record ReadVSegment(byte[] fhandle, long offset, byte[] data) {}

    /** {@code kXR_query} with {@code kXR_Qspace} — {@code oss.*} CGI, bytes.
     *  Quota is -1 when the pool reports none: "no limit", not "no writes". */
    public record SpaceInfo(String name, long total, long free,
                            long largestFree, long used, long quota) {}

    /** {@code kXR_chkpoint} with {@code kXR_ckpQuery}: how large a checkpoint
     *  this server lets a file accumulate, and how much of that is spent.
     *  A server that answers with less than eight bytes reports zero. */
    public record ChkpointLimits(long maxBytes, long usedBytes) {}

    /** One attribute in a {@code kXR_fattr} response. */
    public record FattrItem(String name, int code, byte[] value) {}

    /** {@code kXR_fattr} response body. */
    public record FattrResult(int errors, List<FattrItem> items) {}
}

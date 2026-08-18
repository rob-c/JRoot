package io.github.robc.jroot.client;

import java.io.Closeable;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdException;
import io.github.robc.jroot.XrdServerException;
import io.github.robc.jroot.wire.Requests;
import io.github.robc.jroot.wire.Responses;
import io.github.robc.jroot.wire.Types.ChecksumInfo;
import io.github.robc.jroot.wire.Types.DirEntry;
import io.github.robc.jroot.wire.Types.FattrResult;
import io.github.robc.jroot.wire.Types.LocationInfo;
import io.github.robc.jroot.wire.Types.OpenInfo;
import io.github.robc.jroot.wire.Types.PrepareStatus;
import io.github.robc.jroot.wire.Types.RedirectInfo;
import io.github.robc.jroot.wire.Types.SpaceInfo;
import io.github.robc.jroot.wire.Types.StatInfo;
import io.github.robc.jroot.wire.Types.VfsInfo;
import io.github.robc.jroot.wire.XrdConst;

/**
 * The {@code root://} filesystem: connections, redirects and the operations
 * that do not need an open file.
 *
 * <p>A cluster answers most requests with {@code kXR_redirect} — the manager
 * knows which data server holds the file and says so — which is why nothing
 * here talks to a connection directly. Every operation runs through
 * {@link #execute}, which follows redirects, carries the server's opaque
 * information onto the next request, and reuses connections it has already
 * brought up. Instances are thread-safe and worth sharing: the connection
 * cache is the point.
 */
public final class XrdClient implements Closeable {

    /** The unit a whole-file transfer is cut into: one round trip's worth of
     *  data on a wide-area link, and the granularity a multi-stream transfer
     *  hands to each stream. */
    public static final int TRANSFER_CHUNK = 8 << 20;

    /** The floor on how long a third-party copy may take. */
    private static final Duration TPC_TIMEOUT = Duration.ofHours(1);

    private final Config config;
    private final Map<String, XrdConnection> connections = new ConcurrentHashMap<>();

    public XrdClient() {
        this(Config.defaults());
    }

    public XrdClient(Config config) {
        this.config = config;
    }

    public Config config() {
        return config;
    }

    /** One operation, retried at whatever server the cluster points it to. */
    @FunctionalInterface
    public interface Operation<T> {
        T run(XrdConnection connection, XrdUrl url);
    }

    /** The connection to {@code url}'s server, brought up if there is not one. */
    public XrdConnection connection(XrdUrl url) {
        XrdConnection existing = connections.get(url.serverKey());
        if (existing != null && existing.isOpen()) {
            return existing;
        }
        XrdConnection opened = XrdConnection.open(url, config);
        XrdConnection raced = connections.put(url.serverKey(), opened);
        if (raced != null && raced != opened) {
            raced.close();
        }
        return opened;
    }

    /**
     * Run {@code operation} against {@code url}, following redirects until
     * a server answers or the limit is reached.
     */
    public <T> T execute(XrdUrl url, Operation<T> operation) {
        XrdUrl current = url;
        for (int hop = 0; hop <= config.maxRedirects(); hop++) {
            try {
                return operation.run(connection(current), current);
            } catch (XrdRedirectException e) {
                current = follow(current, e.redirect());
            }
        }
        throw new XrdException(url + " redirected more than " + config.maxRedirects()
                + " times; the cluster is looping");
    }

    /**
     * Where a redirect points. The opaque information the server attached
     * travels with the request from here on — it is how a manager tells the
     * data server what it already decided.
     */
    static XrdUrl follow(XrdUrl url, RedirectInfo redirect) {
        XrdUrl next = url.at(redirect.host(), redirect.actualPort(), redirect.requiresTls());
        if (redirect.opaque().isEmpty()) {
            return next;
        }
        String opaque = redirect.opaque();
        while (!opaque.isEmpty() && (opaque.charAt(0) == '&' || opaque.charAt(0) == '?')) {
            opaque = opaque.substring(1);
        }
        String cgi = url.cgi().isEmpty() ? opaque : url.cgi() + "&" + opaque;
        return next.withCgi(cgi);
    }

    // -----------------------------------------------------------------
    // Metadata
    // -----------------------------------------------------------------

    public StatInfo stat(String url) {
        return stat(XrdUrl.parse(url));
    }

    public StatInfo stat(XrdUrl url) {
        return execute(url, (connection, at) -> Responses.parseStat(
                connection.request(new Requests.Stat(at.pathWithCgi())).data(), at.path()));
    }

    /** Whether a path exists, without making its absence an exception. */
    public boolean exists(String url) {
        try {
            stat(url);
            return true;
        } catch (XrdServerException e) {
            if (e.isNotFound()) {
                return false;
            }
            throw e;
        }
    }

    public Optional<StatInfo> statIfPresent(String url) {
        try {
            return Optional.of(stat(url));
        } catch (XrdServerException e) {
            if (e.isNotFound()) {
                return Optional.empty();
            }
            throw e;
        }
    }

    /** Free space where {@code url} lives. */
    public VfsInfo statVfs(String url) {
        XrdUrl parsed = XrdUrl.parse(url);
        return execute(parsed, (connection, at) -> Responses.parseStatVfs(
                connection.request(new Requests.Stat(at.pathWithCgi(),
                        XrdConst.kXR_vfs, XrdConst.NULL_FHANDLE)).data()));
    }

    /** One flags byte per path, in the order given. */
    public int[] statx(List<String> paths) {
        if (paths.isEmpty()) {
            return new int[0];
        }
        XrdUrl first = XrdUrl.parse(paths.get(0));
        List<String> onlyPaths = paths.stream().map(p -> XrdUrl.parse(p).path()).toList();
        return execute(first, (connection, at) ->
                Responses.parseStatx(connection.request(new Requests.Statx(onlyPaths)).data()));
    }

    /** List a directory. Stat information is requested and used when the
     *  server offers it, which turns an {@code ls -l} into one round trip. */
    public List<DirEntry> list(String url) {
        return list(XrdUrl.parse(url), true);
    }

    public List<DirEntry> list(XrdUrl url, boolean withStat) {
        int options = withStat ? XrdConst.kXR_dstat : 0;
        return execute(url, (connection, at) -> Responses.parseDirlist(
                connection.request(new Requests.Dirlist(at.pathWithCgi(), options)).data(),
                at.path()));
    }

    public List<LocationInfo> locate(String url) {
        return locate(XrdUrl.parse(url), 0);
    }

    public List<LocationInfo> locate(XrdUrl url, int options) {
        return execute(url, (connection, at) -> Responses.parseLocate(
                connection.request(new Requests.Locate(at.pathWithCgi(), options)).data()));
    }

    /**
     * Every data server holding the file, asked of the managers in the way.
     *
     * <p>A federation is a tree of redirectors: {@code kXR_locate} at the top
     * answers with the managers below it, and only the leaves answer with
     * servers. One locate is therefore a list of places to ask rather than a
     * list of replicas, and the answer worth having is what comes back from
     * following it down — which is what {@code XrdCl}'s deep locate does, and
     * what a copy wants before it decides where to read from.
     *
     * <p>Managers already visited are not visited twice, since a federation
     * may name the same one from two places, and a manager that will not
     * answer is skipped rather than fatal: the replicas found elsewhere are
     * still worth returning.
     */
    public List<LocationInfo> deepLocate(String url) {
        XrdUrl parsed = XrdUrl.parse(url);
        List<LocationInfo> servers = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        Deque<XrdUrl> toAsk = new ArrayDeque<>(List.of(parsed));
        while (!toAsk.isEmpty()) {
            XrdUrl at = toAsk.poll();
            List<LocationInfo> answer;
            try {
                answer = locate(at, 0);
            } catch (XrdException e) {
                continue;               // one silent manager is not the whole tree
            }
            for (LocationInfo location : answer) {
                if (!seen.add(location.type() + location.address())) {
                    continue;
                }
                if (location.isManager()) {
                    toAsk.add(at.at(location.address()));
                } else if (location.isServer()) {
                    servers.add(location);
                }
            }
        }
        return servers;
    }

    public ChecksumInfo checksum(String url) {
        XrdUrl parsed = XrdUrl.parse(url);
        return execute(parsed, (connection, at) -> Responses.parseChecksum(
                connection.request(new Requests.Query(XrdConst.kXR_Qcksum,
                        at.pathWithCgi())).data()));
    }

    public SpaceInfo space(String url) {
        XrdUrl parsed = XrdUrl.parse(url);
        return execute(parsed, (connection, at) -> Responses.parseSpace(
                connection.request(new Requests.Query(XrdConst.kXR_Qspace,
                        at.pathWithCgi())).data()));
    }

    /** A raw {@code kXR_query}, for the information types this API does not name. */
    public String query(String url, int infotype, String args) {
        XrdUrl parsed = XrdUrl.parse(url);
        return execute(parsed, (connection, at) -> new String(
                connection.request(new Requests.Query(infotype, args)).data(),
                StandardCharsets.UTF_8).trim());
    }

    public String config(String url, String what) {
        return query(url, XrdConst.kXR_Qconfig, what);
    }

    // -----------------------------------------------------------------
    // Namespace
    // -----------------------------------------------------------------

    public void mkdir(String url, int mode, boolean makePath) {
        XrdUrl parsed = XrdUrl.parse(url);
        execute(parsed, (connection, at) ->
                connection.request(new Requests.Mkdir(at.pathWithCgi(), mode, makePath)));
    }

    public void mkdir(String url) {
        mkdir(url, XrdConst.DEFAULT_DIR_MODE, true);
    }

    public void rm(String url) {
        XrdUrl parsed = XrdUrl.parse(url);
        execute(parsed, (connection, at) ->
                connection.request(new Requests.Rm(at.pathWithCgi())));
    }

    public void rmdir(String url) {
        XrdUrl parsed = XrdUrl.parse(url);
        execute(parsed, (connection, at) ->
                connection.request(new Requests.Rmdir(at.pathWithCgi())));
    }

    /** Rename within one server. Both paths must live on the same server —
     *  the protocol has no notion of moving between them. */
    public void mv(String sourceUrl, String targetUrl) {
        XrdUrl source = XrdUrl.parse(sourceUrl);
        XrdUrl target = XrdUrl.parse(targetUrl);
        if (!source.endpoint().equals(target.endpoint())) {
            throw new XrdException("kXR_mv cannot move between servers: "
                    + source.endpoint() + " and " + target.endpoint());
        }
        execute(source, (connection, at) ->
                connection.request(new Requests.Mv(at.path(), target.path())));
    }

    public void chmod(String url, int mode) {
        XrdUrl parsed = XrdUrl.parse(url);
        execute(parsed, (connection, at) ->
                connection.request(new Requests.Chmod(at.pathWithCgi(), mode)));
    }

    public void truncate(String url, long size) {
        XrdUrl parsed = XrdUrl.parse(url);
        execute(parsed, (connection, at) -> connection.request(
                new Requests.Truncate(at.pathWithCgi(), size, XrdConst.NULL_FHANDLE)));
    }

    /** Ask a staging server to bring files online. Returns its request handle. */
    public String prepare(List<String> urls, int options, int priority) {
        if (urls.isEmpty()) {
            return "";
        }
        XrdUrl first = XrdUrl.parse(urls.get(0));
        List<String> paths = urls.stream().map(u -> XrdUrl.parse(u).pathWithCgi()).toList();
        return execute(first, (connection, at) -> new String(
                connection.request(new Requests.Prepare(paths, options, priority, 0, 0)).data(),
                StandardCharsets.UTF_8).trim());
    }

    /**
     * How the staging {@link #prepare} asked for is going ({@code kXR_QPrep}).
     *
     * <p>{@code prepare} returns as soon as the server has written the request
     * down, which for a tape-backed site is a long time before the files are
     * readable. This is the question with an answer worth waiting on: one
     * status per URL, in the order asked, each of them online once its bytes
     * are on disk.
     */
    public List<PrepareStatus> prepareStatus(String handle, List<String> urls) {
        if (urls.isEmpty()) {
            return List.of();
        }
        XrdUrl first = XrdUrl.parse(urls.get(0));
        List<String> paths = urls.stream().map(u -> XrdUrl.parse(u).path()).toList();
        String args = handle + "\n" + String.join("\n", paths);
        return execute(first, (connection, at) -> Responses.parsePrepareStatus(
                connection.request(new Requests.Query(XrdConst.kXR_QPrep, args)).data(), paths));
    }

    /**
     * Withdraw a staging request. The handle takes the place of the path
     * list, which is what makes this its own method rather than a flag on
     * {@link #prepare}: cancelling names the request, not the files, and
     * passing paths here would ask the server to cancel whichever requests
     * had handles that looked like filenames.
     */
    public void cancelPrepare(String url, String handle) {
        XrdUrl parsed = XrdUrl.parse(url);
        execute(parsed, (connection, at) -> connection.request(
                new Requests.Prepare(List.of(handle), XrdConst.kXR_cancel, 0, 0, 0)));
    }

    // -----------------------------------------------------------------
    // Extended attributes
    // -----------------------------------------------------------------

    public FattrResult getAttribute(String url, String name) {
        XrdUrl parsed = XrdUrl.parse(url);
        return execute(parsed, (connection, at) -> Responses.parseFattr(
                connection.request(Requests.Fattr.get(at.path(), name)).data(), true));
    }

    public FattrResult listAttributes(String url, boolean withValues) {
        XrdUrl parsed = XrdUrl.parse(url);
        return execute(parsed, (connection, at) -> Responses.parseFattr(
                connection.request(Requests.Fattr.list(at.path(), withValues)).data(),
                withValues));
    }

    public void setAttribute(String url, String name, byte[] value) {
        XrdUrl parsed = XrdUrl.parse(url);
        execute(parsed, (connection, at) ->
                connection.request(Requests.Fattr.set(at.path(), name, value, false)));
    }

    public void deleteAttribute(String url, String name) {
        XrdUrl parsed = XrdUrl.parse(url);
        execute(parsed, (connection, at) ->
                connection.request(Requests.Fattr.delete(at.path(), name)));
    }

    // -----------------------------------------------------------------
    // Files
    // -----------------------------------------------------------------

    /** Open for reading. */
    public XrdFile open(String url) {
        return open(url, XrdConst.kXR_open_read | XrdConst.kXR_retstat, 0);
    }

    /** Create or truncate for writing, making parent directories. */
    public XrdFile create(String url, int mode) {
        return open(url, XrdConst.kXR_open_updt | XrdConst.kXR_delete
                | XrdConst.kXR_mkpath | XrdConst.kXR_retstat, mode);
    }

    public XrdFile open(String url, int options, int mode) {
        return open(XrdUrl.parse(url), options, mode);
    }

    public XrdFile open(XrdUrl url, int options, int mode) {
        return execute(url, (connection, at) -> {
            OpenInfo info = Responses.parseOpen(
                    connection.request(new Requests.Open(at.pathWithCgi(), options, mode)).data(),
                    at.path());
            // After the open, not before: a redirect would have thrown, and
            // the server that granted the handle is the one worth binding
            // extra streams to.
            connection.ensureDataPaths();
            return new XrdFile(connection, at, info);
        });
    }

    /** Read a whole file, over every stream the session has. */
    public byte[] read(String url) {
        try (XrdFile file = open(url)) {
            return file.readAll(TRANSFER_CHUNK);
        }
    }

    /** Write a whole file, replacing anything already there. */
    public void write(String url, byte[] data, int mode) {
        try (XrdFile file = create(url, mode)) {
            file.writeAcross(0, data, TRANSFER_CHUNK);
        }
    }

    public void write(String url, byte[] data) {
        write(url, data, 0644);
    }

    // -----------------------------------------------------------------
    // Third-party copy
    // -----------------------------------------------------------------

    /**
     * Have the destination server pull a file straight from the source, so
     * that the bytes never pass through this process.
     *
     * <p>There is no {@code kXR_tpc} request: a third-party copy is arranged
     * entirely through opaque tags on two {@code kXR_open}s that share a
     * rendezvous key.
     *
     * <ol>
     *   <li>A placement open of the source, closed immediately, which is what
     *       resolves the manager to the data server that actually holds the
     *       file — everything after this names that server.</li>
     *   <li>The source open that registers the key and names the destination.
     *       Its handle stays open for the whole transfer: closing it would
     *       unregister the key before the destination arrived to use it.</li>
     *   <li>The destination open, carrying the source, the key and the size,
     *       with {@code kXR_delete|kXR_open_updt} — a plain create is treated
     *       as an ordinary write rather than a pull.</li>
     *   <li>Two {@code kXR_sync} on the destination handle: the first starts
     *       the copy, the second does not answer until it has finished, which
     *       is why it is given {@link #tpcTimeout()} rather than the ordinary
     *       request timeout.</li>
     * </ol>
     *
     * <p>The source is opened for reading with this client's credentials;
     * whether the destination may then read it is the source server's
     * decision, made from the delegation the two servers agree on. This
     * client asks for none ({@code tpc.dlgon=0}), so both ends must already
     * trust each other, which is how a site with a TPC-enabled pair is set up.
     */
    public void thirdPartyCopy(String sourceUrl, String targetUrl) {
        thirdPartyCopy(XrdUrl.parse(sourceUrl), XrdUrl.parse(targetUrl));
    }

    public void thirdPartyCopy(XrdUrl source, XrdUrl target) {
        long size = stat(source).size();
        String key = rendezvousKey();

        XrdUrl at = placementOf(source);
        String srcEndpoint = at.host() + ":" + at.port();
        String srcOpaque = "tpc.dst=" + target.host() + "&tpc.key=" + key + "&tpc.stage=copy";

        try (XrdFile coordinator = open(at.withCgi(append(at.cgi(), srcOpaque)),
                XrdConst.kXR_open_read | XrdConst.kXR_retstat | XrdConst.kXR_async, 0)) {
            String dstOpaque = "oss.asize=" + size
                    + "&tpc.dlg=" + srcEndpoint
                    + "&tpc.dlgon=0"
                    + "&tpc.key=" + key
                    + "&tpc.lfn=" + at.path()
                    + "&tpc.spr=root"
                    + "&tpc.src=" + srcEndpoint
                    + "&tpc.stage=copy"
                    + "&tpc.tpr=root";
            try (XrdFile puller = open(target.withCgi(append(target.cgi(), dstOpaque)),
                    XrdConst.kXR_delete | XrdConst.kXR_open_updt
                            | XrdConst.kXR_retstat | XrdConst.kXR_async,
                    XrdConst.DEFAULT_FILE_MODE)) {
                puller.sync();                      // start the copy
                puller.syncWithin(tpcTimeout());    // and wait it out
            }
        }
    }

    /**
     * How long the destination is given to finish. A transfer is not a
     * request — the file may be a terabyte — so the configured request
     * timeout is only a floor.
     */
    public Duration tpcTimeout() {
        Duration configured = config.requestTimeout();
        return configured.compareTo(TPC_TIMEOUT) > 0 ? configured : TPC_TIMEOUT;
    }

    /** The data server holding {@code source}, found the way the stock client
     *  finds it: an open that asks for nothing but the placement. */
    private XrdUrl placementOf(XrdUrl source) {
        try (XrdFile probe = open(source.withCgi(append(source.cgi(), "tpc.stage=placement")),
                XrdConst.kXR_open_read | XrdConst.kXR_retstat | XrdConst.kXR_async, 0)) {
            // Where the probe landed, with the caller's own opaque back in
            // place: the probe's stage tag has done its work and must not
            // travel on to the open that arranges the copy.
            return probe.url().withCgi(source.cgi());
        } catch (XrdException e) {
            // A server that will not take the probe may still take the copy;
            // the URL as given is then the best guess at where the file is.
            return source;
        }
    }

    /** 12 random bytes as 24 hexadecimal characters, which is the shape of
     *  key every XRootD TPC implementation expects. */
    private static String rendezvousKey() {
        byte[] raw = new byte[12];
        new SecureRandom().nextBytes(raw);
        StringBuilder key = new StringBuilder(raw.length * 2);
        for (byte b : raw) {
            key.append(Character.forDigit((b >> 4) & 0xF, 16))
                    .append(Character.forDigit(b & 0xF, 16));
        }
        return key.toString();
    }

    private static String append(String cgi, String more) {
        return cgi.isEmpty() ? more : cgi + "&" + more;
    }

    /**
     * {@code kXR_gpfile}: ask the server to fetch or deposit a file itself,
     * naming the transfer in the opaque information the path carries.
     *
     * <p>Present for completeness rather than for use. The request is defined
     * in {@code XProtocol.hh} and upstream marks it unfinished; no released
     * server implements it, and one that recognises the opcode at all answers
     * {@code kXR_Unsupported}. A third-party copy is what actually moves a
     * file between servers — see {@link #thirdPartyCopy}.
     *
     * @param options {@link XrdConst#kXR_gpfGet} or {@link XrdConst#kXR_gpfPut}
     * @param bufferSize the transfer buffer to use, or 0 for the server's own
     */
    public String getPutFile(String url, int options, int bufferSize) {
        XrdUrl parsed = XrdUrl.parse(url);
        return execute(parsed, (connection, at) -> new String(
                connection.request(new Requests.GpFile(at.pathWithCgi(), options, bufferSize))
                        .data(), StandardCharsets.UTF_8).trim());
    }

    /** A round trip to prove the connection is alive. */
    public void ping(String url) {
        XrdUrl parsed = XrdUrl.parse(url);
        execute(parsed, (connection, at) -> connection.request(new Requests.Ping()));
    }

    /**
     * {@code kXR_set}: tell a server something about this client. The one
     * directive worth sending is {@code appid <name>}, which is what a site
     * sees beside this client's requests in its logs.
     */
    public void set(String url, String directive) {
        XrdUrl parsed = XrdUrl.parse(url);
        execute(parsed, (connection, at) -> connection.request(new Requests.Set(directive)));
    }

    @Override
    public void close() {
        for (XrdConnection connection : connections.values()) {
            connection.close();
        }
        connections.clear();
    }

    @Override
    public String toString() {
        return "XrdClient" + connections.keySet();
    }
}

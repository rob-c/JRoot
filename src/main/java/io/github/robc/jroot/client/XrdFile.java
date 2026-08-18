package io.github.robc.jroot.client;

import java.io.Closeable;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdConnectionException;
import io.github.robc.jroot.XrdException;
import io.github.robc.jroot.XrdProtocolException;
import io.github.robc.jroot.XrdServerException;
import io.github.robc.jroot.util.Trace;
import io.github.robc.jroot.wire.PagedIo;
import io.github.robc.jroot.wire.Requests;
import io.github.robc.jroot.wire.Responses;
import io.github.robc.jroot.wire.Types;
import io.github.robc.jroot.wire.Types.OpenInfo;
import io.github.robc.jroot.wire.Types.ReadVSegment;
import io.github.robc.jroot.wire.Types.StatInfo;
import io.github.robc.jroot.wire.XrdConst;
import io.github.robc.jroot.wire.XrdRequest;

/**
 * An open file on one data server.
 *
 * <p>Every operation names its own offset — there is no cursor to share
 * between threads, which is what makes a single handle usable from several
 * at once, exactly as the protocol allows. The handle belongs to the
 * connection it was opened on: a file is not followed across a redirect,
 * because the server that granted the handle is the only one that knows it.
 *
 * <p>A session that breaks under an open file is rebuilt rather than
 * reported, for as long as {@link Config#recoveryWindow()} allows: the
 * client reconnects to the same server, opens the same path again, and
 * repeats the request that failed. Every request carries its own offset, so
 * repeating one writes the same bytes to the same place — which is what
 * makes recovery safe here and not in a protocol with a cursor. What cannot
 * be rebuilt is not attempted: a checkpoint is state the lost server held, a
 * clone names another file's handle, and both fail rather than quietly doing
 * something else.
 */
public final class XrdFile implements Closeable {

    /** How many times one page is resent before the link is called broken. */
    private static final int PG_RETRIES = 3;

    /** How long to leave a server that just dropped us before trying again. */
    private static final Duration RETRY_PAUSE = Duration.ofSeconds(2);

    private final XrdClient client;
    private final XrdUrl url;
    private final OpenInfo info;
    private final int options;
    private final int mode;
    private final Object recoveryLock = new Object();

    private volatile Session session;
    private volatile boolean closed;

    /** The connection a file is open on and the handle that server granted.
     *  Neither means anything without the other, and recovery replaces both
     *  at once. */
    private record Session(XrdConnection connection, byte[] fhandle) { }

    XrdFile(XrdClient client, XrdConnection connection, XrdUrl url, OpenInfo info,
            int options, int mode) {
        this.client = client;
        this.url = url;
        this.info = info;
        this.options = options;
        this.mode = mode;
        this.session = new Session(connection, info.fhandle());
    }

    public XrdUrl url() {
        return url;
    }

    public String path() {
        return url.path();
    }

    /** The stat the server returned at open, when {@code kXR_retstat} was asked. */
    public StatInfo openStat() {
        return info.stat().orElse(null);
    }

    /** The file's size, from the open-time stat or a fresh {@code kXR_stat}. */
    public long size() {
        return info.stat().map(StatInfo::size).orElseGet(() -> stat().size());
    }

    public boolean isOpen() {
        return !closed;
    }

    /** Read {@code length} bytes at {@code offset}; short at end of file. */
    public byte[] read(long offset, int length) {
        return read(offset, length, 0);
    }

    /**
     * The same, answered on the bound data path {@code pathid} instead of the
     * control link. Zero is the control link; anything else must be an id
     * this session's {@link #streams()} lists.
     */
    public byte[] read(long offset, int length, int pathid) {
        check();
        if (length < 0) {
            throw new IllegalArgumentException("cannot read " + length + " bytes");
        }
        return call(handle -> new Requests.Read(handle, offset, length, pathid)).data();
    }

    /**
     * The path ids this file's session can spread a transfer over, the
     * control link's zero first. A single-element array means one socket,
     * which is the default and what {@link Config#dataStreams()} raises.
     */
    public int[] streams() {
        int[] paths = session.connection().dataPaths();
        int[] all = new int[paths.length + 1];
        System.arraycopy(paths, 0, all, 1, paths.length);
        return all;
    }

    /** Read the whole file, in {@code chunk}-sized requests. */
    public byte[] readAll(int chunk) {
        long size = size();
        if (size > Integer.MAX_VALUE) {
            throw new XrdException(path() + " is " + size
                    + " bytes, too large to hold in one array");
        }
        return readAcross(0, (int) size, chunk);
    }

    /**
     * Read a range in {@code chunk}-sized requests spread over every stream
     * the session has, one request in flight per stream. The bytes of a read
     * come back down the stream its request named, so with several bound
     * paths several sockets fill different parts of the answer at once —
     * which is what a long fat network needs and a single stream cannot give.
     *
     * <p>With one stream this is the same loop without the threads. Either
     * way the result is short if the file ends inside the range.
     */
    public byte[] readAcross(long offset, int length, int chunk) {
        check();
        if (length < 0) {
            throw new IllegalArgumentException("cannot read " + length + " bytes");
        }
        if (chunk <= 0) {
            throw new IllegalArgumentException("a chunk of " + chunk + " bytes reads nothing");
        }
        byte[] out = new byte[length];
        int[] streams = streams();
        int filled = streams.length == 1 || length <= chunk
                ? readSerially(out, offset, chunk)
                : readConcurrently(out, offset, chunk, streams);
        if (filled == out.length) {
            return out;
        }
        byte[] trimmed = new byte[filled];
        System.arraycopy(out, 0, trimmed, 0, filled);
        return trimmed;
    }

    /** How many bytes of {@code out} were filled before the file ended. */
    private int readSerially(byte[] out, long offset, int chunk) {
        int filled = 0;
        while (filled < out.length) {
            byte[] part = read(offset + filled, Math.min(chunk, out.length - filled));
            if (part.length == 0) {
                break;                              // the file shrank under us
            }
            System.arraycopy(part, 0, out, filled, part.length);
            filled += part.length;
        }
        return filled;
    }

    /**
     * The same, with one chunk in flight per stream. A chunk that comes back
     * short is the end of the file, and since the chunks after it are already
     * in flight the answer is cut at the first such point rather than at
     * whichever thread happened to notice.
     */
    private int readConcurrently(byte[] out, long offset, int chunk, int[] streams) {
        ExecutorService pool = pool(streams.length, "read");
        try {
            List<Future<Integer>> parts = new ArrayList<>();
            for (int at = 0, lane = 0; at < out.length; at += chunk, lane++) {
                int start = at;
                int want = Math.min(chunk, out.length - at);
                int pathid = streams[lane % streams.length];
                parts.add(pool.submit(() -> readInto(out, offset, start, want, pathid)));
            }
            int end = out.length;
            for (int index = 0; index < parts.size(); index++) {
                int start = index * chunk;
                int got = settle(parts.get(index));
                if (got < Math.min(chunk, out.length - start)) {
                    end = Math.min(end, start + got);
                }
            }
            return end;
        } finally {
            pool.shutdownNow();
        }
    }

    /** One chunk, retried at the offsets a short read leaves behind. */
    private int readInto(byte[] out, long offset, int start, int want, int pathid) {
        int filled = 0;
        while (filled < want) {
            byte[] part = read(offset + start + filled, want - filled, pathid);
            if (part.length == 0) {
                break;
            }
            System.arraycopy(part, 0, out, start + filled, part.length);
            filled += part.length;
        }
        return filled;
    }

    /**
     * A scattered read: several ranges of this file in one round trip. The
     * protocol caps a vector at {@value io.github.robc.jroot.wire.XrdConst#VEC_MAXSEGS}
     * segments, so longer vectors are split.
     */
    public List<ReadVSegment> readV(List<long[]> ranges) {
        check();
        List<ReadVSegment> out = new ArrayList<>();
        for (int start = 0; start < ranges.size(); start += XrdConst.VEC_MAXSEGS) {
            List<long[]> batch = ranges.subList(start,
                    Math.min(start + XrdConst.VEC_MAXSEGS, ranges.size()));
            out.addAll(Responses.parseReadV(call(handle -> {
                List<Requests.Segment> segments = new ArrayList<>();
                for (long[] range : batch) {
                    segments.add(new Requests.Segment(handle, range[0], (int) range[1]));
                }
                return new Requests.ReadV(segments);
            }).data()));
        }
        return out;
    }

    /** Read with per-page CRC32C protection, verified before returning. */
    public byte[] pgRead(long offset, int length) {
        check();
        ServerResponse response = call(handle -> new Requests.PgRead(handle, offset, length));
        return PagedIo.unpackPages(offset, response.data());
    }

    public void write(long offset, byte[] data) {
        write(offset, data, 0);
    }

    /** The same, with the data sent down the bound path {@code pathid}
     *  instead of the control link. */
    public void write(long offset, byte[] data, int pathid) {
        check();
        call(handle -> new Requests.Write(handle, offset, data, pathid));
    }

    /**
     * Write a block in {@code chunk}-sized requests spread over every stream
     * the session has. The mirror of {@link #readAcross}: each stream carries
     * its own chunks' bytes, so the sockets fill at once instead of in turn.
     */
    public void writeAcross(long offset, byte[] data, int chunk) {
        check();
        if (chunk <= 0) {
            throw new IllegalArgumentException("a chunk of " + chunk + " bytes writes nothing");
        }
        int[] streams = streams();
        if (streams.length == 1 || data.length <= chunk) {
            write(offset, data);
            return;
        }
        ExecutorService pool = pool(streams.length, "write");
        try {
            List<Future<Integer>> parts = new ArrayList<>();
            for (int at = 0, lane = 0; at < data.length; at += chunk, lane++) {
                int start = at;
                int want = Math.min(chunk, data.length - at);
                int pathid = streams[lane % streams.length];
                parts.add(pool.submit(() -> {
                    byte[] piece = new byte[want];
                    System.arraycopy(data, start, piece, 0, want);
                    write(offset + start, piece, pathid);
                    return want;
                }));
            }
            for (Future<Integer> part : parts) {
                settle(part);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    /** Write with per-page CRC32C protection the server verifies. */
    public void pgWrite(long offset, byte[] data) {
        pgWrite(offset, data, 0);
    }

    /**
     * The same, down the bound path {@code pathid}.
     *
     * <p>A server that finds a page's checksum wrong writes the data anyway
     * and answers with the offsets it could not trust, so the write is only
     * finished once those pages have been sent again and accepted. The
     * encoding here is never the culprit — what these report is corruption
     * on the wire — so resending the same bytes is the whole of the cure,
     * and a page that survives {@value #PG_RETRIES} attempts is a link worth
     * failing on rather than writing over.
     */
    public void pgWrite(long offset, byte[] data, int pathid) {
        check();
        ServerResponse response = call(handle -> new Requests.PgWrite(handle, offset,
                PagedIo.packPages(offset, data), 0, pathid));
        for (long page : PagedIo.corruptPages(response.data())) {
            resend(offset, data, page, pathid);
        }
    }

    /** Drive one page the server rejected back to a clean answer. */
    private void resend(long base, byte[] data, long page, int pathid) {
        long from = page - base;
        if (from < 0 || from >= data.length) {
            throw new XrdProtocolException("the server reported a bad page at offset " + page
                    + ", which is outside the " + data.length + " bytes written at " + base);
        }
        int at = (int) from;
        byte[] bytes = new byte[PagedIo.firstPageLength(page, data.length - at)];
        System.arraycopy(data, at, bytes, 0, bytes.length);
        for (int attempt = 0; attempt < PG_RETRIES; attempt++) {
            ServerResponse retry = call(handle -> new Requests.PgWrite(handle, page,
                    PagedIo.packPages(page, bytes), XrdConst.kXR_pgRetry, pathid));
            if (PagedIo.corruptPages(retry.data()).length == 0) {
                return;
            }
        }
        throw new XrdProtocolException("the page at offset " + page + " was still corrupt after "
                + PG_RETRIES + " retransmissions");
    }

    /** Several writes in one round trip. */
    public void writeV(List<Object[]> chunks, boolean sync) {
        check();
        call(handle -> {
            List<Requests.WriteSegment> segments = new ArrayList<>();
            for (Object[] chunk : chunks) {
                segments.add(new Requests.WriteSegment(handle,
                        (Long) chunk[0], (byte[]) chunk[1]));
            }
            return new Requests.WriteV(segments, sync);
        });
    }

    /** Flush this file's data to storage. */
    public void sync() {
        check();
        call(handle -> new Requests.Sync(handle));
    }

    /**
     * The same, with its own patience. A sync is ordinarily immediate, but
     * the one that drives a third-party copy does not answer until the
     * destination has pulled the whole file.
     */
    public void syncWithin(java.time.Duration timeout) {
        check();
        call(handle -> new Requests.Sync(handle), timeout);
    }

    public void truncate(long size) {
        check();
        call(handle -> new Requests.Truncate("", size, handle));
    }

    // -----------------------------------------------------------------
    // Checkpoints
    // -----------------------------------------------------------------

    /**
     * Open a checkpoint on this file. Until {@link #commit()} the server
     * keeps enough of the old contents to undo every write and truncate
     * made through {@link #writeChecked} and {@link #truncateChecked}, and
     * {@link #rollback()} puts the file back as it was.
     */
    public void checkpoint() {
        check();
        session.connection().request(Requests.Chkpoint.begin(session.fhandle()));
    }

    /** Make the checkpointed writes permanent and drop the undo data. */
    public void commit() {
        check();
        session.connection().request(Requests.Chkpoint.commit(session.fhandle()));
    }

    /** Undo everything written since {@link #checkpoint()}. */
    public void rollback() {
        check();
        session.connection().request(Requests.Chkpoint.rollback(session.fhandle()));
    }

    /** How much more this file may write under the open checkpoint. */
    public Types.ChkpointLimits checkpointLimits() {
        check();
        return Responses.parseChkpoint(session.connection()
                .request(Requests.Chkpoint.query(session.fhandle())).data());
    }

    /** A write that the open checkpoint can undo. */
    public void writeChecked(long offset, byte[] data) {
        check();
        Session on = session;
        on.connection().request(Requests.Chkpoint.exec(on.fhandle(),
                new Requests.Write(on.fhandle(), offset, data)));
    }

    /** A truncate that the open checkpoint can undo. */
    public void truncateChecked(long size) {
        check();
        Session on = session;
        on.connection().request(Requests.Chkpoint.exec(on.fhandle(),
                new Requests.Truncate("", size, on.fhandle())));
    }

    public StatInfo stat() {
        check();
        return Responses.parseStat(
                call(handle -> new Requests.Stat("", 0, handle)).data(), path());
    }

    // -----------------------------------------------------------------
    // Server-side copy
    // -----------------------------------------------------------------

    /** The server's handle for this file, copied: the array on the wire is
     *  the connection's and must not be edited under it. */
    public byte[] handle() {
        return session.fhandle().clone();
    }

    /**
     * {@code kXR_clone}: have the server copy ranges out of another file it
     * already has open into this one, so that the bytes never leave it.
     *
     * <p>This is <em>not</em> a stock XRootD request — it sits past
     * {@code kXR_REQFENCE} and comes from the nginx-xrootd server, whose
     * implementation this encoder matches. A stock server answers
     * {@code kXR_InvalidRequest}, which is the correct thing for it to do.
     *
     * <p>Both files must be open on the same connection: a file handle means
     * nothing to a server that did not grant it.
     */
    public void cloneFrom(XrdFile source, long sourceOffset, long length, long offset) {
        cloneFrom(source, List.of(new long[] {sourceOffset, length, offset}));
    }

    /** Several ranges of one file, {@code {sourceOffset, length, offset}} each. */
    public void cloneFrom(XrdFile source, List<long[]> ranges) {
        check();
        if (source.session.connection() != session.connection()) {
            throw new XrdException(source.path() + " is open on another connection than "
                    + path() + "; a file handle means nothing to a server that did not"
                    + " grant it");
        }
        List<Requests.CloneItem> items = new ArrayList<>();
        for (long[] range : ranges) {
            items.add(new Requests.CloneItem(source.session.fhandle(),
                    range[0], range[1], range[2]));
        }
        cloneFrom(items);
    }

    /** The general form: ranges from any set of files open on this
     *  connection. Longer lists are split at the server's own item limit. */
    public void cloneFrom(List<Requests.CloneItem> items) {
        check();
        Session on = session;
        for (int start = 0; start < items.size(); start += XrdConst.CLONE_MAXITEMS) {
            on.connection().request(new Requests.Clone(on.fhandle(), items.subList(start,
                    Math.min(start + XrdConst.CLONE_MAXITEMS, items.size()))));
        }
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        Session on = session;
        try {
            on.connection().request(new Requests.Close(on.fhandle()));
        } catch (XrdConnectionException e) {
            // The handle went when the session did; there is nothing left to
            // give back, and a caller closing a file should not learn about
            // the link that way.
            Trace.debug(Trace.XROOTD, "%s: closed with the session already gone (%s)",
                    path(), e.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // Talking to the server, and going back for the session when it breaks
    // -----------------------------------------------------------------

    /**
     * Send one request built around this file's handle, rebuilding the
     * session first if the link is what failed.
     *
     * <p>The request is built from the handle rather than handed in already
     * built, because after recovery the handle is a different one: the
     * server that granted the first has gone, and the request has to be made
     * again against the second.
     */
    private ServerResponse call(Function<byte[], XrdRequest> build) {
        return call(build, null);
    }

    /** The same, for a request the server may sit on longer than usual. */
    private ServerResponse call(Function<byte[], XrdRequest> build, Duration timeout) {
        Session current = session;
        try {
            return send(current, build, timeout);
        } catch (XrdConnectionException e) {
            return send(recover(current, e), build, timeout);
        }
    }

    private static ServerResponse send(Session on, Function<byte[], XrdRequest> build,
                                       Duration timeout) {
        XrdRequest request = build.apply(on.fhandle());
        return timeout == null ? on.connection().request(request)
                : on.connection().request(request, timeout);
    }

    /**
     * Open this file again on a new connection to the same server, and keep
     * trying until {@link Config#recoveryWindow()} runs out.
     *
     * <p>Only the link is worth waiting on. A server that answers — with
     * "no such file", with "not authorised", with a redirect somewhere it
     * would rather this client went — has told us something that will not
     * change in the next two seconds, so its answer ends the attempt instead
     * of starting another.
     *
     * <p>Threads that failed together recover once: the first through takes
     * the lock, and the others find the session already replaced and use it.
     */
    private Session recover(Session stale, XrdConnectionException cause) {
        if (closed || client == null || client.config().recoveryWindow().isZero()) {
            throw cause;
        }
        Duration window = client.config().recoveryWindow();
        synchronized (recoveryLock) {
            if (session != stale) {
                return session;                     // somebody else has been here
            }
            long deadline = System.nanoTime() + window.toNanos();
            XrdException last = cause;
            for (int attempt = 1; ; attempt++) {
                Trace.warn(Trace.CONNECTION, "%s: session lost (%s); reopening, attempt %d",
                        path(), last.getMessage(), attempt);
                try {
                    Session rebuilt = reopen();
                    Trace.info(Trace.CONNECTION, "%s: session rebuilt on %s",
                            path(), rebuilt.connection().url().serverKey());
                    session = rebuilt;
                    return rebuilt;
                } catch (XrdServerException | XrdRedirectException e) {
                    throw new XrdConnectionException(path() + " lost its session, and "
                            + url.serverKey() + " will not open it again: " + e.getMessage(), e);
                } catch (XrdException e) {
                    last = e;
                }
                if (System.nanoTime() + RETRY_PAUSE.toNanos() >= deadline) {
                    throw new XrdConnectionException(path() + " could not be reopened within "
                            + window.toSeconds() + "s of losing its session: "
                            + last.getMessage(), last);
                }
                pause();
            }
        }
    }

    /** The same path, on the same server, opened afresh. */
    private Session reopen() {
        XrdConnection fresh = client.connection(url);
        OpenInfo reopened = Responses.parseOpen(fresh.request(
                new Requests.Open(url.pathWithCgi(), reopenOptions(), mode)).data(), url.path());
        fresh.ensureDataPaths();
        return new Session(fresh, reopened.fhandle());
    }

    /**
     * What to open with the second time. Everything about creating the file
     * is dropped: it exists by now, and asking for it to be made new — or
     * deleted first — would throw away every byte written before the link
     * broke, which is the one outcome recovery exists to avoid.
     */
    private int reopenOptions() {
        int creation = XrdConst.kXR_delete | XrdConst.kXR_new | XrdConst.kXR_mkpath;
        return (options & ~creation) | (isWriting() ? XrdConst.kXR_open_updt : 0);
    }

    private boolean isWriting() {
        int writes = XrdConst.kXR_open_updt | XrdConst.kXR_open_wrto
                | XrdConst.kXR_open_apnd | XrdConst.kXR_delete | XrdConst.kXR_new;
        return (options & writes) != 0;
    }

    private static void pause() {
        try {
            Thread.sleep(RETRY_PAUSE.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new XrdConnectionException("interrupted while rebuilding a lost session", e);
        }
    }

    private void check() {
        if (closed) {
            throw new XrdException(path() + " is closed");
        }
    }

    /** One daemon thread per stream, named for whoever has to read a stack. */
    private ExecutorService pool(int threads, String what) {
        AtomicInteger next = new AtomicInteger();
        return Executors.newFixedThreadPool(threads, runnable -> {
            Thread thread = new Thread(runnable,
                    "jroot-" + what + "-" + url.host() + "-" + next.getAndIncrement());
            thread.setDaemon(true);
            return thread;
        });
    }

    /** A chunk's result, with the exception it failed with put back as it
     *  was thrown — a server error stays an {@link XrdException} even though
     *  it came out of another thread. */
    private int settle(Future<Integer> part) {
        try {
            return part.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new XrdException("interrupted transferring " + path(), e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof XrdException xrd) {
                throw xrd;
            }
            if (cause instanceof RuntimeException runtime) {
                throw runtime;
            }
            throw new XrdException("transferring " + path() + " failed: "
                    + cause.getMessage(), cause);
        }
    }

    @Override
    public String toString() {
        return "XrdFile[" + url + (closed ? ", closed" : "") + "]";
    }
}

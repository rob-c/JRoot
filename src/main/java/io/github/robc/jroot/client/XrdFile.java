package io.github.robc.jroot.client;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.List;

import io.github.robc.jroot.XrdException;
import io.github.robc.jroot.wire.PagedIo;
import io.github.robc.jroot.wire.Requests;
import io.github.robc.jroot.wire.Responses;
import io.github.robc.jroot.wire.Types;
import io.github.robc.jroot.wire.Types.OpenInfo;
import io.github.robc.jroot.wire.Types.ReadVSegment;
import io.github.robc.jroot.wire.Types.StatInfo;
import io.github.robc.jroot.wire.XrdConst;

/**
 * An open file on one data server.
 *
 * <p>Every operation names its own offset — there is no cursor to share
 * between threads, which is what makes a single handle usable from several
 * at once, exactly as the protocol allows. The handle belongs to the
 * connection it was opened on: a file is not followed across a redirect,
 * because the server that granted the handle is the only one that knows it.
 */
public final class XrdFile implements Closeable {

    private final XrdConnection connection;
    private final XrdUrl url;
    private final byte[] fhandle;
    private final OpenInfo info;
    private volatile boolean closed;

    XrdFile(XrdConnection connection, XrdUrl url, OpenInfo info) {
        this.connection = connection;
        this.url = url;
        this.fhandle = info.fhandle();
        this.info = info;
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
        check();
        if (length < 0) {
            throw new IllegalArgumentException("cannot read " + length + " bytes");
        }
        return connection.request(new Requests.Read(fhandle, offset, length)).data();
    }

    /** Read the whole file, in {@code chunk}-sized requests. */
    public byte[] readAll(int chunk) {
        long size = size();
        if (size > Integer.MAX_VALUE) {
            throw new XrdException(path() + " is " + size
                    + " bytes, too large to hold in one array");
        }
        byte[] out = new byte[(int) size];
        int filled = 0;
        while (filled < out.length) {
            byte[] part = read(filled, Math.min(chunk, out.length - filled));
            if (part.length == 0) {
                break;                              // the file shrank under us
            }
            System.arraycopy(part, 0, out, filled, part.length);
            filled += part.length;
        }
        if (filled == out.length) {
            return out;
        }
        byte[] trimmed = new byte[filled];
        System.arraycopy(out, 0, trimmed, 0, filled);
        return trimmed;
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
            List<Requests.Segment> segments = new ArrayList<>();
            for (long[] range : ranges.subList(start,
                    Math.min(start + XrdConst.VEC_MAXSEGS, ranges.size()))) {
                segments.add(new Requests.Segment(fhandle, range[0], (int) range[1]));
            }
            out.addAll(Responses.parseReadV(
                    connection.request(new Requests.ReadV(segments)).data()));
        }
        return out;
    }

    /** Read with per-page CRC32C protection, verified before returning. */
    public byte[] pgRead(long offset, int length) {
        check();
        ServerResponse response =
                connection.request(new Requests.PgRead(fhandle, offset, length));
        return PagedIo.unpackPages(offset, response.data());
    }

    public void write(long offset, byte[] data) {
        check();
        connection.request(new Requests.Write(fhandle, offset, data));
    }

    /** Write with per-page CRC32C protection the server verifies. */
    public void pgWrite(long offset, byte[] data) {
        check();
        connection.request(new Requests.PgWrite(fhandle, offset,
                PagedIo.packPages(offset, data)));
    }

    /** Several writes in one round trip. */
    public void writeV(List<Object[]> chunks, boolean sync) {
        check();
        List<Requests.WriteSegment> segments = new ArrayList<>();
        for (Object[] chunk : chunks) {
            segments.add(new Requests.WriteSegment(fhandle,
                    (Long) chunk[0], (byte[]) chunk[1]));
        }
        connection.request(new Requests.WriteV(segments, sync));
    }

    /** Flush this file's data to storage. */
    public void sync() {
        check();
        connection.request(new Requests.Sync(fhandle));
    }

    public void truncate(long size) {
        check();
        connection.request(new Requests.Truncate("", size, fhandle));
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
        connection.request(Requests.Chkpoint.begin(fhandle));
    }

    /** Make the checkpointed writes permanent and drop the undo data. */
    public void commit() {
        check();
        connection.request(Requests.Chkpoint.commit(fhandle));
    }

    /** Undo everything written since {@link #checkpoint()}. */
    public void rollback() {
        check();
        connection.request(Requests.Chkpoint.rollback(fhandle));
    }

    /** How much more this file may write under the open checkpoint. */
    public Types.ChkpointLimits checkpointLimits() {
        check();
        return Responses.parseChkpoint(
                connection.request(Requests.Chkpoint.query(fhandle)).data());
    }

    /** A write that the open checkpoint can undo. */
    public void writeChecked(long offset, byte[] data) {
        check();
        connection.request(Requests.Chkpoint.exec(fhandle,
                new Requests.Write(fhandle, offset, data)));
    }

    /** A truncate that the open checkpoint can undo. */
    public void truncateChecked(long size) {
        check();
        connection.request(Requests.Chkpoint.exec(fhandle,
                new Requests.Truncate("", size, fhandle)));
    }

    public StatInfo stat() {
        check();
        return Responses.parseStat(
                connection.request(new Requests.Stat("", 0, fhandle)).data(), path());
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        connection.request(new Requests.Close(fhandle));
    }

    private void check() {
        if (closed) {
            throw new XrdException(path() + " is closed");
        }
    }

    @Override
    public String toString() {
        return "XrdFile[" + url + (closed ? ", closed" : "") + "]";
    }
}

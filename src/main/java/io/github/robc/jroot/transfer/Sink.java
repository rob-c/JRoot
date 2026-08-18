package io.github.robc.jroot.transfer;

import java.io.Closeable;

/**
 * A writable end of a copy, told where each piece belongs.
 *
 * <p>Offsets rather than an append, for the same reason {@link Source} reads
 * them: a copy that pulls several chunks at once finishes them out of order,
 * and the destination has to take them that way. Implementations must
 * tolerate concurrent writes to disjoint ranges.
 */
public interface Sink extends Closeable {

    void write(long offset, byte[] data);

    @Override
    void close();
}

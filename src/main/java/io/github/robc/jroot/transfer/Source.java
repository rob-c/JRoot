package io.github.robc.jroot.transfer;

import java.io.Closeable;

/**
 * A readable end of a copy: a size, and random access to the bytes behind it.
 *
 * <p>Random access rather than a stream, because that is what makes the
 * interesting copies possible — several chunks in flight at once, over
 * several streams or from several replicas, reassembled by offset rather
 * than by arrival. A source that can only be read forwards can still
 * implement this; it simply will not go faster for having been asked twice.
 */
public interface Source extends Closeable {

    /** The file's length, or a negative number when the far end will not say. */
    long size();

    /**
     * {@code length} bytes from {@code offset}, or fewer at the end of the
     * file. An empty array means there was nothing left to read.
     */
    byte[] read(long offset, int length);

    @Override
    void close();
}

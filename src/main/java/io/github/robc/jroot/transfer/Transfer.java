package io.github.robc.jroot.transfer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import io.github.robc.jroot.JRoot;
import io.github.robc.jroot.XrdException;
import io.github.robc.jroot.client.XrdUrl;
import io.github.robc.jroot.util.Env;
import io.github.robc.jroot.wire.Types.ChecksumInfo;
import io.github.robc.jroot.wire.Types.LocationInfo;
import io.github.robc.jroot.wire.XrdConst;
import io.github.robc.jroot.zip.ZipArchive;

/**
 * A copy, with everything that makes one survive a real grid.
 *
 * <p>{@link JRoot#copy} is a byte pump: one source, one chunk at a time, and
 * any failure ends it. That is the right thing for a copy between two hosts
 * that are up. It is not what {@code xrdcp} does, and the difference is the
 * whole of this class:
 *
 * <ul>
 *   <li><b>Several sources at once.</b> A file on the grid has replicas. Given
 *       more than one URL — from a metalink, from a redirector's
 *       {@code kXR_locate}, or simply listed by the caller — the chunks are
 *       drawn from all of them in parallel, which is the "extreme copy" the
 *       XRootD client names it.
 *   <li><b>Failover.</b> A source that errors is dropped and its chunk handed
 *       to another, so one sick pool node costs a retry rather than the
 *       transfer. A copy only fails once every replica has failed it.
 *   <li><b>Verification.</b> The point of a checksum is to compare two ends,
 *       and a copy that does not do it has moved bytes without establishing
 *       that they are the right ones.
 *   <li><b>Progress.</b> Told as it happens, because a transfer measured in
 *       hours needs to say so before it finishes.
 * </ul>
 *
 * <p>Verification is a second pass rather than a running sum, because chunks
 * arrive out of order and a running sum cannot be fed out of order. That
 * costs nothing where it matters: both ends compute their own, server-side,
 * and only a local file is read back — off local disk, at local speed.
 */
public final class Transfer {

    /** Told how a transfer is getting on, from whichever thread got there. */
    @FunctionalInterface
    public interface Progress {
        /** {@code total} is negative when the source would not say how big it is. */
        void advanced(long done, long total);
    }

    /** What a finished transfer amounted to. */
    public record Result(String target, long bytes, Duration elapsed, List<String> sources,
                         String algorithm, String checksum, boolean verified) {

        public double bytesPerSecond() {
            double seconds = elapsed.toNanos() / 1e9;
            return seconds <= 0 ? 0 : bytes / seconds;
        }

        @Override
        public String toString() {
            return String.format("%d bytes to %s in %.1fs (%.1f MB/s)%s",
                    bytes, target, elapsed.toNanos() / 1e9, bytesPerSecond() / (1 << 20),
                    verified ? ", " + algorithm + " verified" : "");
        }
    }

    /**
     * What to copy and how hard to try. Immutable, with a {@code with…} for
     * each field, in the shape {@code Config} has.
     */
    public record Plan(List<String> sources, String target, int chunkSize, int parallel,
                       int retries, boolean verify, String algorithm, String expected,
                       Progress progress) {

        public Plan {
            sources = List.copyOf(sources);
        }

        public static Plan of(String source, String target) {
            return of(List.of(source), target);
        }

        public static Plan of(List<String> sources, String target) {
            return new Plan(sources, target, DEFAULT_CHUNK, DEFAULT_PARALLEL, DEFAULT_RETRIES,
                    true, Checksum.DEFAULT, "", null);
        }

        public Plan withChunkSize(int value) {
            return new Plan(sources, target, value, parallel, retries, verify, algorithm,
                    expected, progress);
        }

        public Plan withParallel(int value) {
            return new Plan(sources, target, chunkSize, value, retries, verify, algorithm,
                    expected, progress);
        }

        public Plan withRetries(int value) {
            return new Plan(sources, target, chunkSize, parallel, value, verify, algorithm,
                    expected, progress);
        }

        public Plan withVerify(boolean value) {
            return new Plan(sources, target, chunkSize, parallel, retries, value, algorithm,
                    expected, progress);
        }

        public Plan withAlgorithm(String value) {
            return new Plan(sources, target, chunkSize, parallel, retries, verify,
                    Checksum.normalise(value), expected, progress);
        }

        /** The checksum the source is known to have, from wherever it was learnt. */
        public Plan withExpected(String value) {
            return new Plan(sources, target, chunkSize, parallel, retries, verify, algorithm,
                    value == null ? "" : value, progress);
        }

        public Plan withProgress(Progress value) {
            return new Plan(sources, target, chunkSize, parallel, retries, verify, algorithm,
                    expected, value);
        }

        public Plan withSources(List<String> value) {
            return new Plan(value, target, chunkSize, parallel, retries, verify, algorithm,
                    expected, progress);
        }
    }

    /** Big enough to amortise a round trip, small enough to spread evenly. */
    public static final int DEFAULT_CHUNK = 8 << 20;

    /** Chunks in flight. The XRootD client's own default is the same number. */
    public static final int DEFAULT_PARALLEL = 4;

    /** How many other replicas one chunk may be asked of before giving up. */
    public static final int DEFAULT_RETRIES = 3;

    private final JRoot jroot;

    public Transfer(JRoot jroot) {
        this.jroot = jroot;
    }

    // -----------------------------------------------------------------
    // Running one
    // -----------------------------------------------------------------

    public Result copy(String source, String target) {
        return run(plan(List.of(source), target));
    }

    public Result copy(List<String> sources, String target) {
        return run(plan(sources, target));
    }

    /**
     * A plan with the defaults the {@code XRD_*} environment asks for, which
     * is how a site tunes {@code xrdcp} on its worker nodes:
     * {@code XRD_CPCHUNKSIZE} sets how much one request moves and
     * {@code XRD_CPPARALLELCHUNKS} how many are in flight. {@link Plan#of}
     * is the same thing with this library's own defaults and no environment
     * in it at all.
     */
    public static Plan plan(List<String> sources, String target) {
        Plan plan = Plan.of(sources, target);
        int chunk = Env.number("XRD_CPCHUNKSIZE", 4096, 1 << 30);
        if (chunk > 0) {
            plan = plan.withChunkSize(chunk);
        }
        int parallel = Env.number("XRD_CPPARALLELCHUNKS", 1, 128);
        if (parallel > 0) {
            plan = plan.withParallel(parallel);
        }
        return plan;
    }

    public Result run(Plan plan) {
        Plan resolved = resolve(plan);
        if (resolved.sources().isEmpty()) {
            throw new XrdException("a copy needs a source");
        }
        long started = System.nanoTime();
        long bytes = JRoot.transportOf(resolved.target()) == JRoot.Transport.HTTP
                ? throughATemporaryFile(resolved)
                : pull(resolved, resolved.target());
        Duration elapsed = Duration.ofNanos(System.nanoTime() - started);
        return verify(resolved, bytes, elapsed);
    }

    /**
     * An HTTP destination is written by one {@code PUT} of the whole object,
     * so there is no offset to pull chunks into. The parallel read still
     * pays off — it just lands on local disk first, and the upload follows.
     */
    private long throughATemporaryFile(Plan plan) {
        Path staged = null;
        try {
            staged = Files.createTempFile("jroot-", ".part");
            long bytes = pull(plan, staged.toUri().toString());
            jroot.webdav().write(plan.target(), staged);
            return bytes;
        } catch (IOException e) {
            throw new XrdException("cannot stage a copy of " + plan.sources().get(0)
                    + ": " + e.getMessage(), e);
        } finally {
            if (staged != null) {
                try {
                    Files.deleteIfExists(staged);
                } catch (IOException ignored) {
                    // A temporary file the operating system will collect.
                }
            }
        }
    }

    /**
     * The transfer proper: every chunk of the file, drawn from whichever
     * replica is free and working, written where it belongs.
     */
    private long pull(Plan plan, String target) {
        Replicas replicas = new Replicas(jroot, plan.sources(), plan.parallel());
        try {
            long size = replicas.size();
            if (size < 0) {
                // No replica would say how big it is, so there is nothing to
                // divide between them: read it through, one chunk after the next.
                return single(plan, replicas, target);
            }
            int chunkSize = Math.max(plan.chunkSize(), 1);
            ConcurrentLinkedQueue<Long> queue = new ConcurrentLinkedQueue<>();
            for (long at = 0; at < size; at += chunkSize) {
                queue.add(at);
            }
            if (size == 0) {
                queue.add(0L);          // create an empty file rather than nothing
            }
            AtomicLong done = new AtomicLong();
            try (Sink sink = jroot.sink(target)) {
                int workers = Math.max(1, Math.min(plan.parallel(), queue.size()));
                ExecutorService pool = pool(workers);
                try {
                    List<Future<?>> running = new ArrayList<>(workers);
                    for (int i = 0; i < workers; i++) {
                        running.add(pool.submit(() -> {
                            for (Long at = queue.poll(); at != null; at = queue.poll()) {
                                int want = (int) Math.min(chunkSize, size - at);
                                byte[] chunk = replicas.read(at, want, plan.retries());
                                sink.write(at, chunk);
                                report(plan, done.addAndGet(chunk.length), size);
                            }
                            return null;
                        }));
                    }
                    for (Future<?> part : running) {
                        settle(part, target);
                    }
                } finally {
                    pool.shutdownNow();
                }
            }
            return done.get();
        } finally {
            replicas.close();
        }
    }

    /** A source of unknown length: read until it stops giving bytes. */
    private long single(Plan plan, Replicas replicas, String target) {
        long at = 0;
        try (Sink sink = jroot.sink(target)) {
            while (true) {
                byte[] chunk = replicas.read(at, Math.max(plan.chunkSize(), 1), plan.retries());
                if (chunk.length == 0) {
                    break;
                }
                sink.write(at, chunk);
                at += chunk.length;
                report(plan, at, -1);
            }
        }
        return at;
    }

    // -----------------------------------------------------------------
    // Where the sources come from
    // -----------------------------------------------------------------

    /**
     * Turn what the caller named into the list actually worth reading from.
     *
     * <p>A metalink is fetched and unfolded into its replicas, bringing the
     * publisher's checksum with it. A {@code root://} URL with no siblings is
     * asked of its redirector, since a manager knows every data server
     * holding the file and one of them may be having a bad day. Anything else
     * is taken as given.
     */
    Plan resolve(Plan plan) {
        Plan out = plan;
        if (plan.sources().size() == 1 && Metalink.looksLikeOne(plan.sources().get(0))) {
            Metalink.Entry entry = fetchMetalink(plan.sources().get(0));
            out = out.withSources(entry.urls());
            Optional<Map.Entry<String, String>> checksum = entry.checksum();
            if (plan.expected().isEmpty() && checksum.isPresent()) {
                out = out.withAlgorithm(checksum.get().getKey())
                        .withExpected(checksum.get().getValue());
            }
        }
        if (out.sources().size() == 1 && out.parallel() > 1
                && JRoot.transportOf(out.sources().get(0)) == JRoot.Transport.XROOTD) {
            out = out.withSources(spread(out.sources().get(0)));
        }
        return memberChecksum(out);
    }

    /**
     * A ZIP member carries its own CRC32 in the archive's directory, and that
     * is what a copy of it should be checked against. Whatever the server
     * says about the archive is the checksum of the archive, which says
     * nothing at all about one member taken out of it.
     */
    private Plan memberChecksum(Plan plan) {
        if (plan.sources().isEmpty()) {
            return plan;            // run() has the complaint for that
        }
        String source = plan.sources().get(0);
        Optional<String> member = ZipArchive.memberOf(source);
        if (member.isEmpty() || !plan.expected().isEmpty()) {
            return plan;
        }
        try (ZipArchive archive = jroot.zip(source)) {
            Optional<ZipArchive.Member> found = archive.member(member.get());
            if (found.isEmpty() || found.get().crc32() == 0) {
                return plan;
            }
            return plan.withAlgorithm("crc32")
                    .withExpected(String.format("%08x", found.get().crc32()));
        } catch (XrdException e) {
            // The copy itself will fail on the same archive in a moment, and
            // with a better message than this one would carry.
            return plan;
        }
    }

    private Metalink.Entry fetchMetalink(String url) {
        List<Metalink.Entry> files = Metalink.parse(jroot.read(url));
        if (files.size() > 1) {
            throw new XrdException(url + " is a metalink naming " + files.size()
                    + " files; copy them one at a time");
        }
        return files.get(0);
    }

    /**
     * Every data server holding this file, as URLs. A manager answers
     * {@code kXR_locate} with the lot; a data server answers with itself, in
     * which case there is nothing to spread and the URL is left alone.
     */
    List<String> spread(String url) {
        List<String> found = new ArrayList<>();
        try {
            XrdUrl parsed = XrdUrl.parse(url);
            Set<String> seen = new LinkedHashSet<>();
            for (LocationInfo location : jroot.xrootd().locate(url)) {
                if (!location.isServer() || !seen.add(location.address())) {
                    continue;
                }
                found.add(at(parsed, location).toString());
            }
        } catch (XrdException e) {
            // A server that will not answer kXR_locate is a server that
            // holds the file itself. There is nothing to spread.
            return List.of(url);
        }
        return found.isEmpty() ? List.of(url) : found;
    }

    /**
     * {@code kXR_locate} answers with {@code host:port}, and IPv6 wears
     * brackets there as it does in a URL, so the port is the colon after the
     * last bracket rather than the first colon in the string.
     */
    static XrdUrl at(XrdUrl url, LocationInfo location) {
        String address = location.address();
        int colon = address.lastIndexOf(':');
        int bracket = address.lastIndexOf(']');
        if (colon < 0 || colon < bracket) {
            return url.at(address, XrdConst.DEFAULT_PORT, false);
        }
        String host = address.substring(0, colon);
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        try {
            return url.at(host, Integer.parseInt(address.substring(colon + 1)), false);
        } catch (NumberFormatException e) {
            return url.at(address, XrdConst.DEFAULT_PORT, false);
        }
    }

    // -----------------------------------------------------------------
    // Establishing it arrived intact
    // -----------------------------------------------------------------

    /**
     * Compare what the two ends say the file checksums to.
     *
     * <p>The expected value comes from the metalink if there was one, else
     * from the source server. The actual value comes from the destination. A
     * server that will compute one is asked to; a local file is read back.
     * When neither end will produce a checksum the copy is reported unverified
     * rather than failed — plenty of storage carries no checksum at all, and
     * refusing those transfers would be refusing to work.
     */
    private Result verify(Plan plan, long bytes, Duration elapsed) {
        String algorithm = Checksum.normalise(plan.algorithm());
        if (!plan.verify()) {
            return new Result(plan.target(), bytes, elapsed, plan.sources(), algorithm, "", false);
        }
        String against = plan.sources().get(0);
        String expected = plan.expected();
        if (expected.isEmpty()) {
            // Whichever replica will say. The first one on the list is not
            // necessarily one that opened — the copy may have failed over
            // past it — so ask down the list until one answers.
            for (String source : plan.sources()) {
                expected = checksumOf(source, algorithm);
                if (!expected.isEmpty()) {
                    against = source;
                    break;
                }
            }
        }
        String actual = checksumOf(plan.target(), algorithm);
        if (expected.isEmpty() || actual.isEmpty()) {
            return new Result(plan.target(), bytes, elapsed, plan.sources(), algorithm,
                    actual.isEmpty() ? expected : actual, false);
        }
        if (!Checksum.same(expected, actual)) {
            throw new XrdException(plan.target() + " does not checksum to what "
                    + against + " does: " + algorithm + " " + actual
                    + " where " + expected + " was expected; the copy is not the file");
        }
        return new Result(plan.target(), bytes, elapsed, plan.sources(), algorithm, actual, true);
    }

    /** What {@code url} checksums to, or nothing if it cannot be established. */
    String checksumOf(String url, String algorithm) {
        if (ZipArchive.memberOf(url).isPresent()) {
            // Asking the server would answer about the archive, not the
            // member; the member's own CRC32 is used instead.
            return "";
        }
        try {
            Optional<ChecksumInfo> answer = jroot.checksum(url, algorithm);
            if (answer.isPresent() && !answer.get().value().isBlank()
                    && Checksum.normalise(answer.get().algorithm()).equals(algorithm)) {
                return answer.get().value();
            }
        } catch (XrdException e) {
            // A server with no checksum configured says so by failing.
        }
        if (JRoot.transportOf(url) == JRoot.Transport.LOCAL && Checksum.supports(algorithm)) {
            // Local disk, so reading it back to compute one costs nothing
            // that crosses a network.
            try (Source source = jroot.source(url)) {
                return Checksum.of(algorithm, source);
            } catch (XrdException e) {
                // A replica that is not there is not a replica to ask.
                return "";
            }
        }
        return "";
    }

    // -----------------------------------------------------------------
    // Plumbing
    // -----------------------------------------------------------------

    /**
     * The replicas of one file, opened as they are first needed and dropped
     * as they fail. Chunks are handed out round-robin, so a slow replica
     * carries fewer of them without anybody having to measure it.
     */
    private static final class Replicas {

        private final JRoot jroot;
        private final Deque<String> pending;
        private final List<Source> open = new ArrayList<>();
        private final AtomicInteger next = new AtomicInteger();
        private final int maxOpen;
        private XrdException lastFailure;
        private long size = Long.MIN_VALUE;

        Replicas(JRoot jroot, List<String> urls, int maxOpen) {
            this.jroot = jroot;
            this.pending = new ArrayDeque<>(urls);
            this.maxOpen = Math.max(1, maxOpen);
        }

        /**
         * How big the file is, according to the first replica that opens.
         * Opening one is also what proves the list is not entirely dead,
         * which is worth learning before a sink truncates the destination.
         */
        synchronized long size() {
            if (size == Long.MIN_VALUE) {
                size = pick().size();
            }
            return size;
        }

        byte[] read(long offset, int length, int retries) {
            XrdException last = null;
            for (int attempt = 0; attempt <= Math.max(retries, 0); attempt++) {
                Source source = pick();
                try {
                    return source.read(offset, length);
                } catch (XrdException e) {
                    last = e;
                    drop(source);
                }
            }
            throw last != null ? last : new XrdException(
                    "no replica would give " + length + " bytes at " + offset);
        }

        /**
         * A replica to read from. One more is opened whenever there are
         * fewer open than there are chunks in flight, so the connections
         * grow to the width of the transfer and no further.
         */
        private synchronized Source pick() {
            if (open.size() < maxOpen) {
                openOneMore();
            }
            if (open.isEmpty()) {
                throw lastFailure != null ? lastFailure
                        : new XrdException("a copy needs a source that opens");
            }
            return open.get(Math.floorMod(next.getAndIncrement(), open.size()));
        }

        /** Take the next candidate that opens, discarding the ones that do not. */
        private void openOneMore() {
            while (!pending.isEmpty()) {
                String url = pending.poll();
                try {
                    open.add(jroot.source(url));
                    return;
                } catch (XrdException e) {
                    lastFailure = e;
                }
            }
        }

        private synchronized void drop(Source source) {
            if (!open.remove(source)) {
                return;                 // another thread got there first
            }
            try {
                source.close();
            } catch (RuntimeException ignored) {
                // It was already failing; how it closes is not the news.
            }
        }

        synchronized void close() {
            for (Source source : open) {
                try {
                    source.close();
                } catch (RuntimeException ignored) {
                    // Nothing left to do about it.
                }
            }
            open.clear();
        }
    }

    private void report(Plan plan, long done, long total) {
        Progress progress = plan.progress();
        if (progress == null) {
            return;
        }
        synchronized (progress) {
            progress.advanced(done, total);
        }
    }

    private static ExecutorService pool(int threads) {
        AtomicInteger next = new AtomicInteger();
        return Executors.newFixedThreadPool(threads, runnable -> {
            Thread thread = new Thread(runnable, "jroot-copy-" + next.getAndIncrement());
            thread.setDaemon(true);
            return thread;
        });
    }

    private static void settle(Future<?> part, String target) {
        try {
            part.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new XrdException("interrupted copying to " + target, e);
        } catch (java.util.concurrent.ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof XrdException xrd) {
                throw xrd;
            }
            if (cause instanceof RuntimeException runtime) {
                throw runtime;
            }
            throw new XrdException("copying to " + target + " failed: "
                    + cause.getMessage(), cause);
        }
    }

    @Override
    public String toString() {
        return "Transfer[" + jroot + "]";
    }
}

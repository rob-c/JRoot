package io.github.robc.jroot;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;

import io.github.robc.jroot.transfer.Transfer;
import io.github.robc.jroot.wire.Types.ChecksumInfo;
import io.github.robc.jroot.wire.Types.DirEntry;
import io.github.robc.jroot.wire.Types.StatInfo;

/**
 * The same operations {@link JRoot} offers, handed to a pool and answered
 * with a {@link CompletableFuture} — for a caller with a thousand files to
 * stat and no interest in doing it one at a time.
 *
 * <p>This is the blocking API run elsewhere, and it says so: the protocol
 * underneath is request and response, and there is no callback layer hiding
 * in here pretending otherwise. What makes it worth having is that XRootD
 * multiplexes requests over one connection per server — each carries its own
 * stream id and the answers are matched back by it — so a hundred outstanding
 * calls to one door are a hundred requests in flight on one socket, not a
 * hundred sockets.
 *
 * <p>A failure arrives as the {@link XrdException} it would have been, inside
 * the {@code CompletionException} the framework wraps it in.
 *
 * <pre>{@code
 * try (JRoot jroot = JRoot.open()) {
 *     List<CompletableFuture<StatInfo>> all = urls.stream()
 *             .map(jroot.async()::stat).toList();
 *     CompletableFuture.allOf(all.toArray(CompletableFuture[]::new)).join();
 * }
 * }</pre>
 */
public final class Async implements AutoCloseable {

    /** Enough to keep a door busy without becoming a load test of it. */
    public static final int DEFAULT_THREADS = 8;

    private final JRoot jroot;
    private final ExecutorService pool;
    private final boolean ownsPool;

    Async(JRoot jroot, ExecutorService pool, boolean ownsPool) {
        this.jroot = jroot;
        this.pool = pool;
        this.ownsPool = ownsPool;
    }

    static ExecutorService pool(int threads) {
        AtomicInteger next = new AtomicInteger();
        return Executors.newFixedThreadPool(threads, runnable -> {
            Thread thread = new Thread(runnable, "jroot-async-" + next.getAndIncrement());
            thread.setDaemon(true);
            return thread;
        });
    }

    // -----------------------------------------------------------------
    // Anything at all
    // -----------------------------------------------------------------

    /**
     * Run something against the client on the pool. Everything else here is
     * this with a name, and anything this class does not name is still
     * reachable through it.
     */
    public <T> CompletableFuture<T> submit(Function<JRoot, T> work) {
        return CompletableFuture.supplyAsync(() -> work.apply(jroot), pool);
    }

    public CompletableFuture<Void> run(Consumer<JRoot> work) {
        return CompletableFuture.runAsync(() -> work.accept(jroot), pool);
    }

    // -----------------------------------------------------------------
    // The operations worth naming
    // -----------------------------------------------------------------

    public CompletableFuture<StatInfo> stat(String url) {
        return submit(jroot -> jroot.stat(url));
    }

    public CompletableFuture<Optional<StatInfo>> statIfPresent(String url) {
        return submit(jroot -> jroot.statIfPresent(url));
    }

    public CompletableFuture<List<DirEntry>> list(String url) {
        return submit(jroot -> jroot.list(url));
    }

    public CompletableFuture<List<DirEntry>> listTree(String url) {
        return submit(jroot -> jroot.listTree(url));
    }

    public CompletableFuture<byte[]> read(String url) {
        return submit(jroot -> jroot.read(url));
    }

    public CompletableFuture<byte[]> read(String url, long offset, int length) {
        return submit(jroot -> jroot.read(url, offset, length));
    }

    public CompletableFuture<Void> write(String url, byte[] data) {
        return run(jroot -> jroot.write(url, data));
    }

    public CompletableFuture<Optional<ChecksumInfo>> checksum(String url, String algorithm) {
        return submit(jroot -> jroot.checksum(url, algorithm));
    }

    public CompletableFuture<Transfer.Result> copy(String source, String target) {
        return submit(jroot -> jroot.transfer().copy(source, target));
    }

    public CompletableFuture<Transfer.Result> copy(Transfer.Plan plan) {
        return submit(jroot -> jroot.transfer().run(plan));
    }

    public CompletableFuture<Transfer.TreeResult> copyTree(String source, String target) {
        return submit(jroot -> jroot.transfer().copyTree(source, target));
    }

    public CompletableFuture<Void> mkdir(String url, boolean makePath) {
        return run(jroot -> jroot.mkdir(url, makePath));
    }

    public CompletableFuture<Void> rm(String url) {
        return run(jroot -> jroot.rm(url));
    }

    public CompletableFuture<Void> rmTree(String url) {
        return run(jroot -> jroot.rmTree(url));
    }

    /**
     * Give back the pool if this object made it. A pool the caller supplied
     * is the caller's to shut down, since it may well be running other work.
     */
    @Override
    public void close() {
        if (ownsPool) {
            pool.shutdownNow();
        }
    }

    @Override
    public String toString() {
        return "Async[" + jroot + "]";
    }
}

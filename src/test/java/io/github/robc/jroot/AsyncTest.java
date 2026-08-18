package io.github.robc.jroot;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import io.github.robc.jroot.http.MockHttpStorage;
import io.github.robc.jroot.wire.Types.StatInfo;

/** The same client, asked for a hundred things at once. */
@Timeout(60)
class AsyncTest {

    @TempDir
    Path dir;

    private JRoot jroot;

    @BeforeEach
    void open() {
        jroot = JRoot.open();
    }

    @AfterEach
    void close() {
        jroot.close();
    }

    @Test
    void answersAHundredQuestionsWithoutBeingAskedOneAtATime() throws IOException {
        List<String> files = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            Path file = Files.write(dir.resolve("f" + i + ".root"),
                    ("event " + i).getBytes(UTF_8));
            files.add(file.toString());
        }

        List<CompletableFuture<StatInfo>> stats =
                files.stream().map(jroot.async()::stat).toList();
        CompletableFuture.allOf(stats.toArray(CompletableFuture[]::new)).join();

        for (int i = 0; i < files.size(); i++) {
            assertEquals(("event " + i).length(), stats.get(i).join().size());
        }
    }

    @Test
    void readsFromStorageInParallel() throws IOException {
        byte[] content = "a histogram".repeat(100).getBytes(UTF_8);
        try (MockHttpStorage storage = new MockHttpStorage()) {
            storage.put("/store/f.root", content);
            List<CompletableFuture<byte[]>> reads = new ArrayList<>();
            for (int i = 0; i < 20; i++) {
                reads.add(jroot.async().read(storage.url("/store/f.root")));
            }
            for (CompletableFuture<byte[]> read : reads) {
                assertArrayEquals(content, read.join());
            }
        }
    }

    @Test
    void bringsTheFailureBackTheWayItHappened() {
        CompletableFuture<StatInfo> missing =
                jroot.async().stat(dir.resolve("gone.root").toString());

        CompletionException wrapper = assertThrows(CompletionException.class, missing::join);
        XrdServerException failure = assertInstanceOf(XrdServerException.class,
                wrapper.getCause());
        assertTrue(failure.isNotFound(), failure.getMessage());
    }

    @Test
    void copiesAndRemovesWithoutBlockingTheCaller() throws IOException {
        byte[] content = "a run".repeat(1000).getBytes(UTF_8);
        Path source = Files.write(dir.resolve("source.root"), content);
        Path target = dir.resolve("copy.root");

        assertTrue(jroot.async().copy(source.toString(), target.toString()).join().verified());
        assertArrayEquals(content, Files.readAllBytes(target));

        jroot.async().rm(target.toString()).join();
        assertFalse(Files.exists(target));
    }

    @Test
    void runsWhateverItWasNotToldAbout() throws IOException {
        Files.write(dir.resolve("one.root"), "one".getBytes(UTF_8));

        assertEquals(1, jroot.async()
                .submit(client -> client.list(dir.toString()).size()).join());
        assertTrue(jroot.async()
                .submit(client -> client.stat(dir.toString()).isDirectory()).join());
    }

    @Test
    void leavesAPoolItWasGivenRunning() {
        ExecutorService mine = Executors.newSingleThreadExecutor();
        try (Async async = jroot.async(mine)) {
            assertTrue(async.submit(client -> client.stat(dir.toString()).isDirectory()).join());
        }
        assertFalse(mine.isShutdown(), "a pool the caller owns was shut down for it");
        mine.shutdownNow();
    }

    @Test
    void handsBackTheSameFaceEveryTime() {
        assertEquals(jroot.async(), jroot.async());
        assertTrue(jroot.async().toString().startsWith("Async["), jroot.async().toString());
    }

    @Test
    void stopsAcceptingWorkOnceTheClientIsClosed() {
        Async async = jroot.async();
        jroot.close();
        assertThrows(java.util.concurrent.RejectedExecutionException.class,
                () -> async.stat(dir.toString()));
        jroot = JRoot.open();       // so the teardown has something to close
    }
}

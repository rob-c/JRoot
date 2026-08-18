package io.github.robc.jroot.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertLinesMatch;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.JRoot;
import io.github.robc.jroot.wire.WBuf;
import io.github.robc.jroot.wire.XrdConst;

/**
 * Whole-tree operations over the binary protocol, against a server that
 * really holds a tree: the recursion is the client's, so the order it removes
 * and creates things in is what these tests are about.
 */
@Timeout(30)
class TreeTest {

    private static final byte[] CONTENT =
            "the quick brown fox".getBytes(StandardCharsets.UTF_8);

    private static Config config() {
        return Config.defaults().withTls(Config.Tls.DISABLED).withAllowUnix(true);
    }

    /**
     * A directory tree the mock answers {@code kXR_stat} and
     * {@code kXR_dirlist} from: a path maps to its children, and a path
     * absent from the map is a file.
     */
    private static final Map<String, List<String>> TREE = new LinkedHashMap<>(Map.of(
            "/store", List.of("run1", "top.root"),
            "/store/run1", List.of("a.root", "sub"),
            "/store/run1/sub", List.of("b.root")));

    /** What the request asked for, opaque data and all. */
    private static String target(MockXrootd.Request request) {
        return request.text().split("\0")[0];
    }

    /** The path alone, which is what a server looks up. */
    private static String path(MockXrootd.Request request) {
        String target = target(request);
        int query = target.indexOf('?');
        return query < 0 ? target : target.substring(0, query);
    }

    private static MockXrootd tree(List<String> removed, List<String> made) throws IOException {
        MockXrootd server = new MockXrootd();
        server.on(XrdConst.kXR_stat, MockXrootd.answering(request -> {
                    int flags = TREE.containsKey(path(request))
                            ? XrdConst.kXR_isDir : XrdConst.kXR_file;
                    return MockXrootd.Reply.ok(MockXrootd.statLine("id", CONTENT.length,
                            flags | XrdConst.kXR_readable, 7));
                }))
                .on(XrdConst.kXR_dirlist, MockXrootd.answering(request ->
                        MockXrootd.Reply.ok(dirlist(path(request)))))
                .on(XrdConst.kXR_rm, MockXrootd.answering(request -> {
                    removed.add(target(request));
                    return MockXrootd.Reply.ok(new byte[0]);
                }))
                .on(XrdConst.kXR_rmdir, MockXrootd.answering(request -> {
                    removed.add(target(request));
                    return MockXrootd.Reply.ok(new byte[0]);
                }))
                .on(XrdConst.kXR_mkdir, MockXrootd.answering(request -> {
                    made.add(path(request));
                    return MockXrootd.Reply.ok(new byte[0]);
                }))
                .on(XrdConst.kXR_open, MockXrootd.answering(request -> MockXrootd.Reply.ok(
                        new WBuf().raw(new byte[] {1, 2, 3, 4})
                                .i32(XrdConst.kXR_pgPageSZ).text("adlr", false)
                                .raw(MockXrootd.statLine("id", CONTENT.length, 0, 7))
                                .bytes())))
                .on(XrdConst.kXR_read, MockXrootd.answering(request -> {
                    int from = (int) Math.min(request.offset(), CONTENT.length);
                    int length = Math.min(request.length(), CONTENT.length - from);
                    byte[] slice = new byte[Math.max(length, 0)];
                    System.arraycopy(CONTENT, from, slice, 0, slice.length);
                    return MockXrootd.Reply.ok(slice);
                }));
        return server;
    }

    /** A {@code kXR_dstat} listing: "." and its stat line, then each child
     *  and its own. */
    private static byte[] dirlist(String path) {
        StringBuilder text = new StringBuilder(".\n0 0 " + XrdConst.kXR_isDir + " 0\n");
        for (String name : TREE.getOrDefault(path, List.of())) {
            String child = path + "/" + name;
            int flags = TREE.containsKey(child) ? XrdConst.kXR_isDir : XrdConst.kXR_file;
            text.append(name).append('\n')
                    .append("id ").append(CONTENT.length).append(' ').append(flags)
                    .append(" 7\n");
        }
        return text.toString().getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void removesATreeFromTheLeavesUpwards() throws IOException {
        List<String> removed = new ArrayList<>();
        try (MockXrootd server = tree(removed, new ArrayList<>());
             JRoot jroot = JRoot.open(config())) {
            jroot.rmTree(server.url("/store"));
        }
        assertLinesMatch(List.of(
                "/store/run1/a.root",
                "/store/run1/sub/b.root",
                "/store/run1/sub",
                "/store/run1",
                "/store/top.root",
                "/store"), removed);
    }

    @Test
    void removesAPlainFileWithoutListingAnything() throws IOException {
        List<String> removed = new ArrayList<>();
        try (MockXrootd server = tree(removed, new ArrayList<>());
             JRoot jroot = JRoot.open(config())) {
            jroot.rmTree(server.url("/store/top.root"));
            assertEquals(List.of("/store/top.root"), removed);
            assertTrue(server.opcodes().stream().noneMatch(o -> o == XrdConst.kXR_dirlist));
        }
    }

    @Test
    void copiesATreeDownToTheLocalFilesystem(@TempDir Path directory) throws IOException {
        Path target = directory.resolve("copy");
        try (MockXrootd server = tree(new ArrayList<>(), new ArrayList<>());
             JRoot jroot = JRoot.open(config())) {
            jroot.copyTree(server.url("/store"), target.toString());
        }
        assertTrue(Files.isDirectory(target.resolve("run1/sub")));
        assertEquals(new String(CONTENT, StandardCharsets.UTF_8),
                Files.readString(target.resolve("run1/sub/b.root")));
        assertEquals(new String(CONTENT, StandardCharsets.UTF_8),
                Files.readString(target.resolve("top.root")));
    }

    @Test
    void createsEveryDirectoryItCopiesInto(@TempDir Path directory) throws IOException {
        List<String> made = new ArrayList<>();
        try (MockXrootd server = tree(new ArrayList<>(), made);
             JRoot jroot = JRoot.open(config())) {
            Files.writeString(directory.resolve("one.root"), "one");
            Files.createDirectory(directory.resolve("deep"));
            Files.writeString(directory.resolve("deep/two.root"), "two");
            jroot.copyTree(directory.toString(), server.url("/store/new"));
        }
        assertLinesMatch(List.of("/store/new", "/store/new/deep"), made);
    }

    @Test
    void carriesOpaqueDataDownTheTreeWithoutPuttingItInThePath() throws IOException {
        List<String> removed = new ArrayList<>();
        try (MockXrootd server = tree(removed, new ArrayList<>());
             JRoot jroot = JRoot.open(config())) {
            jroot.rmTree(server.url("/store/run1?authz=token"));
        }
        // A token that authorises the parent authorises the children too, so
        // it has to survive the recursion — appended after the path, which is
        // the only place a server will read it.
        assertLinesMatch(List.of(
                "/store/run1/a.root?authz=token",
                "/store/run1/sub/b.root?authz=token",
                "/store/run1/sub?authz=token",
                "/store/run1?authz=token"), removed);
    }
}

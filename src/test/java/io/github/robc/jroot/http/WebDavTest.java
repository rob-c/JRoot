package io.github.robc.jroot.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdException;
import io.github.robc.jroot.XrdServerException;
import io.github.robc.jroot.wire.Types.DirEntry;
import io.github.robc.jroot.wire.Types.StatInfo;
import io.github.robc.jroot.wire.XrdConst;

/** {@link WebDav} against a real server answering real multistatus documents. */
@Timeout(30)
class WebDavTest {

    private static final byte[] CONTENT = "some data".getBytes(StandardCharsets.UTF_8);

    private static Config config() {
        return Config.defaults().withToken("s3cret");
    }

    @Test
    void statsWithPropfindRatherThanHead() throws IOException {
        try (MockHttpStorage server = new MockHttpStorage().put("/data/file", CONTENT);
             WebDav dav = new WebDav(config())) {
            StatInfo stat = dav.stat(server.url("/data/file"));
            assertEquals(CONTENT.length, stat.size());
            assertEquals("/data/file", stat.path());
            assertFalse(stat.isDirectory());
            assertEquals(List.of("PROPFIND /data/file"), server.log());
            assertEquals("0", server.headers().get(0).getFirst("Depth"));
        }
    }

    @Test
    void seesACollectionAsADirectory() throws IOException {
        try (MockHttpStorage server = new MockHttpStorage().collection("/data");
             WebDav dav = new WebDav(config())) {
            assertTrue(dav.stat(server.url("/data")).isDirectory());
        }
    }

    @Test
    void listsTheChildrenAndNotTheCollection() throws IOException {
        try (MockHttpStorage server = new MockHttpStorage()
                     .collection("/data").collection("/data/sub")
                     .put("/data/one.root", CONTENT).put("/data/two.root", CONTENT)
                     .put("/elsewhere", CONTENT);
             WebDav dav = new WebDav(config())) {
            List<DirEntry> entries = dav.list(server.url("/data"));
            assertEquals(List.of("one.root", "two.root", "sub"),
                    entries.stream().map(DirEntry::name).toList());
            assertEquals("/data", entries.get(0).parent());
            assertEquals(CONTENT.length, entries.get(0).stat().orElseThrow().size());
            assertTrue(entries.get(2).isDirectory());
            assertEquals("1", server.headers().get(0).getFirst("Depth"));
        }
    }

    @Test
    void makesACollection() throws IOException {
        try (MockHttpStorage server = new MockHttpStorage();
             WebDav dav = new WebDav(config())) {
            dav.mkdir(server.url("/data"));
            assertTrue(server.has("/data"));
        }
    }

    @Test
    void refusesToRemakeACollectionUnlessMakingAPath() throws IOException {
        try (MockHttpStorage server = new MockHttpStorage().collection("/data");
             WebDav dav = new WebDav(config())) {
            XrdServerException failure = assertThrows(XrdServerException.class,
                    () -> dav.mkdir(server.url("/data")));
            assertEquals(XrdConst.kXR_ItExists, failure.code());
        }
    }

    @Test
    void makesEveryMissingParent() throws IOException {
        try (MockHttpStorage server = new MockHttpStorage();
             WebDav dav = new WebDav(config())) {
            dav.mkdir(server.url("/a/b/c"), true);
            assertTrue(server.has("/a"));
            assertTrue(server.has("/a/b"));
            assertTrue(server.has("/a/b/c"));
            assertEquals(List.of("MKCOL /a/", "MKCOL /a/b/", "MKCOL /a/b/c"), server.log());
        }
    }

    @Test
    void movesAnObject() throws IOException {
        try (MockHttpStorage server = new MockHttpStorage().put("/data/one", CONTENT);
             WebDav dav = new WebDav(config())) {
            dav.move(server.url("/data/one"), server.url("/data/two"));
            assertArrayEquals(CONTENT, server.contentOf("/data/two"));
            assertFalse(server.has("/data/one"));
            assertEquals(server.url("/data/two"),
                    server.headers().get(0).getFirst("Destination"));
            assertEquals("T", server.headers().get(0).getFirst("Overwrite"));
        }
    }

    @Test
    void removesACollection() throws IOException {
        try (MockHttpStorage server = new MockHttpStorage().collection("/data");
             WebDav dav = new WebDav(config())) {
            dav.rmdir(server.url("/data"));
            assertFalse(server.has("/data"));
        }
    }

    @Test
    void runsAThirdPartyCopyAsAPull() throws IOException {
        try (MockHttpStorage destination = new MockHttpStorage();
             MockHttpStorage source = new MockHttpStorage().put("/data/file", CONTENT);
             WebDav dav = new WebDav(config())) {
            dav.thirdPartyCopy(source.url("/data/file"), destination.url("/data/file"));
            assertEquals(List.of("COPY /data/file"), destination.log(),
                    "the destination is the end asked to do the work");
            assertEquals(source.url("/data/file"),
                    destination.headers().get(0).getFirst("Source"));
            assertEquals("Bearer s3cret",
                    destination.headers().get(0).getFirst("TransferHeaderAuthorization"));
            assertTrue(source.log().isEmpty(), "the client never touches the source");
        }
    }

    @Test
    void sendsTheFarEndCredentialWhenGivenOne() throws IOException {
        try (MockHttpStorage destination = new MockHttpStorage();
             MockHttpStorage source = new MockHttpStorage();
             WebDav dav = new WebDav(config())) {
            dav.thirdPartyCopy(source.url("/data/file"), destination.url("/data/file"),
                    false, "other-end", true);
            assertEquals(List.of("COPY /data/file"), source.log(),
                    "a push asks the source to send");
            assertEquals(destination.url("/data/file"),
                    source.headers().get(0).getFirst("Destination"));
            assertEquals("Bearer other-end",
                    source.headers().get(0).getFirst("TransferHeaderAuthorization"));
        }
    }

    @Test
    void failsAThirdPartyCopyThatEndedInFailure() throws IOException {
        try (MockHttpStorage destination = new MockHttpStorage()
                     .copyEnding("failure: no space left on device");
             MockHttpStorage source = new MockHttpStorage();
             WebDav dav = new WebDav(config())) {
            XrdServerException failure = assertThrows(XrdServerException.class,
                    () -> dav.thirdPartyCopy(source.url("/f"), destination.url("/f")));
            assertEquals(XrdConst.kXR_ServerError, failure.code());
            assertTrue(failure.getMessage().contains("no space left on device"));
        }
    }

    @Test
    void refusesAThirdPartyCopyThatNeverSaidHowItEnded() throws IOException {
        try (MockHttpStorage destination = new MockHttpStorage().copySilent();
             MockHttpStorage source = new MockHttpStorage();
             WebDav dav = new WebDav(config())) {
            XrdException failure = assertThrows(XrdException.class,
                    () -> dav.thirdPartyCopy(source.url("/f"), destination.url("/f")));
            assertTrue(failure.getMessage().contains("without saying"));
        }
    }

    @Test
    void replaysThePropfindBodyThroughARedirect() throws IOException {
        try (MockHttpStorage door = new MockHttpStorage();
             MockHttpStorage pool = new MockHttpStorage().put("/data/file", CONTENT);
             WebDav dav = new WebDav(config())) {
            door.redirectingTo(pool.url("/data/file"));
            assertEquals(CONTENT.length, dav.stat(door.url("/data/file")).size());
            assertEquals(List.of("PROPFIND /data/file"), pool.log());
        }
    }

    @Test
    void resolvesAnHrefAgainstTheRequestUri() {
        URI base = URI.create("https://host:8443/data/dir");
        assertEquals("/data/dir/one", WebDav.pathOf("/data/dir/one", base));
        assertEquals("/data/dir/one", WebDav.pathOf(
                "https://host:8443/data/dir/one", base));
        assertEquals("/data/dir/one two", WebDav.pathOf("/data/dir/one%20two", base));
        // A collection's href keeps its trailing slash; trimming it is the
        // caller's business, because that is what says it is a collection.
        assertEquals("/data/dir/one/", WebDav.pathOf("/data/dir/one/", base));
    }

    @Test
    void ignoresAPropstatThatFailed() throws IOException {
        // Every mock response carries a second propstat with 404, as real
        // servers send for properties they do not hold; the size must still
        // come from the successful one.
        try (MockHttpStorage server = new MockHttpStorage().put("/f", CONTENT);
             WebDav dav = new WebDav(config())) {
            assertEquals(CONTENT.length, dav.stat(server.url("/f")).size());
        }
    }

    @Test
    void refusesAnXmlDocumentWithADoctype() {
        byte[] hostile = ("<?xml version=\"1.0\"?><!DOCTYPE m [<!ENTITY x SYSTEM "
                + "\"file:///etc/passwd\">]><D:multistatus xmlns:D=\"DAV:\">"
                + "<D:response><D:href>&x;</D:href></D:response></D:multistatus>")
                .getBytes(StandardCharsets.UTF_8);
        assertThrows(XrdException.class, () -> WebDav.parseMultistatus(
                hostile, URI.create("https://host/data")));
    }
}

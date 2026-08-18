package io.github.robc.jroot.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdProtocolException;
import io.github.robc.jroot.XrdServerException;
import io.github.robc.jroot.util.Json;
import io.github.robc.jroot.wire.Types.PrepareStatus;

/**
 * The WLCG Tape REST API against a server on the loopback.
 *
 * <p>The reply bodies are the ones dCache's own models produce — a
 * {@code files} array of {@code path}/{@code state} objects for a staging
 * request, and {@code path}/{@code locality} for {@code archiveinfo} — so a
 * change that broke a real deployment breaks here first.
 */
@Timeout(30)
class TapeTest {

    private static final String ROOT = "/api/v1/tape";

    private static Config config() {
        return Config.defaults().withToken("s3cret");
    }

    // -----------------------------------------------------------------
    // Where the API lives
    // -----------------------------------------------------------------

    @Test
    void asksTheSiteWhereItsTapeApiLives() throws IOException {
        try (MockTapeServer server = new MockTapeServer().publishing("/tape/v1");
             TapeApi tape = new TapeApi(config())) {
            assertEquals(server.url("/tape/v1"), tape.root(server.url("/store/file")).toString());
        }
    }

    @Test
    void asksOnlyOncePerHost() throws IOException {
        try (MockTapeServer server = new MockTapeServer().publishing("/tape/v1");
             TapeApi tape = new TapeApi(config())) {
            tape.root(server.url("/store/one"));
            tape.root(server.url("/store/two"));
            assertEquals(1, server.calls().stream()
                    .filter(call -> call.path().equals(TapeApi.WELL_KNOWN)).count());
        }
    }

    @Test
    void fallsBackToTheUsualRootWhenNothingIsPublished() throws IOException {
        try (MockTapeServer server = new MockTapeServer();
             TapeApi tape = new TapeApi(config())) {
            assertEquals(server.url(ROOT), tape.root(server.url("/store/file")).toString());
        }
    }

    @Test
    void takesADiscoveryDocumentThatNamesEndpointsAsBareStrings() throws IOException {
        try (MockTapeServer server = new MockTapeServer();
             TapeApi tape = new TapeApi(config())) {
            server.answering(TapeApi.WELL_KNOWN, 200,
                    "{\"endpoints\":[\"" + server.url("/api/v1") + "\"]}");
            assertEquals(server.url("/api/v1"), tape.root(server.url("/store/file")).toString());
        }
    }

    // -----------------------------------------------------------------
    // Staging
    // -----------------------------------------------------------------

    @Test
    void submitsAStageRequestAndReadsBackTheHandle() throws IOException {
        try (MockTapeServer server = new MockTapeServer();
             TapeApi tape = new TapeApi(config())) {
            server.answering(ROOT + "/stage", 201, "{\"requestId\":\"cafe-1234\"}");

            assertEquals("cafe-1234", tape.stage(
                    List.of(server.url("/store/one"), server.url("/store/two")), "P1D"));

            Object body = Json.parse(server.call("POST", ROOT + "/stage").body());
            List<Object> files = Json.array(Json.object(body).get("files"));
            assertEquals(2, files.size());
            assertEquals("/store/one", Json.text(files.get(0), "path"));
            assertEquals("/store/two", Json.text(files.get(1), "path"));
            assertEquals("P1D", Json.text(files.get(0), "diskLifetime"));
        }
    }

    @Test
    void leavesTheLifetimeToTheSiteWhenNobodyAsksForOne() throws IOException {
        try (MockTapeServer server = new MockTapeServer();
             TapeApi tape = new TapeApi(config())) {
            server.answering(ROOT + "/stage", 201, "{\"requestId\":\"x\"}");
            tape.stage(List.of(server.url("/store/one")));

            Object files = Json.object(
                    Json.parse(server.call("POST", ROOT + "/stage").body())).get("files");
            assertFalse(Json.object(Json.array(files).get(0)).containsKey("diskLifetime"));
        }
    }

    @Test
    void takesTheHandleFromTheLocationWhenTheBodyOmitsIt() throws IOException {
        try (MockTapeServer server = new MockTapeServer();
             TapeApi tape = new TapeApi(config())) {
            server.answering(ROOT + "/stage", 201, "{}",
                    "https://store.example.org/api/v1/tape/stage/beef-9/");

            assertEquals("beef-9", tape.stage(List.of(server.url("/store/one"))));
        }
    }

    @Test
    void staysQuietWhenThereIsNothingToStage() throws IOException {
        try (MockTapeServer server = new MockTapeServer();
             TapeApi tape = new TapeApi(config())) {
            assertEquals("", tape.stage(List.of()));
            assertEquals(List.of(), tape.archiveInfo(List.of()));
            assertTrue(server.calls().isEmpty());
        }
    }

    @Test
    void refusesARequestTheServerTookButWouldNotName() throws IOException {
        try (MockTapeServer server = new MockTapeServer();
             TapeApi tape = new TapeApi(config())) {
            server.answering(ROOT + "/stage", 201, "{}");

            XrdProtocolException e = assertThrows(XrdProtocolException.class,
                    () -> tape.stage(List.of(server.url("/store/one"))));
            assertTrue(e.getMessage().contains("named no request id"), e.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // How the staging is going
    // -----------------------------------------------------------------

    @Test
    void reportsAFileAsOnlineOnceItIsStaged() throws IOException {
        try (MockTapeServer server = new MockTapeServer();
             TapeApi tape = new TapeApi(config())) {
            server.answering(ROOT + "/stage/cafe", 200, """
                    {"id":"cafe","createdAt":1668516326,"files":[
                      {"path":"/store/one","state":"COMPLETED","startedAt":1668516327},
                      {"path":"/store/two","state":"STARTED","startedAt":1668516328},
                      {"path":"/store/three","state":"FAILED","error":"no such file"}]}
                    """);

            List<PrepareStatus> status = tape.status(server.url("/store/one"), "cafe",
                    List.of(server.url("/store/one"), server.url("/store/two"),
                            server.url("/store/three")));

            assertTrue(status.get(0).online());
            assertFalse(status.get(0).onTape());
            assertEquals("1668516327", status.get(0).requestedAt());

            assertFalse(status.get(1).online());
            assertTrue(status.get(1).onTape(), "still where staging fetches it from");
            assertEquals("STARTED", status.get(1).state());

            assertFalse(status.get(2).online());
            assertFalse(status.get(2).onTape(), "the server has given up on it");
            assertEquals("no such file", status.get(2).error());
        }
    }

    @Test
    void believesAServerThatSaysOnDiskWithoutSayingCompleted() throws IOException {
        try (MockTapeServer server = new MockTapeServer();
             TapeApi tape = new TapeApi(config())) {
            server.answering(ROOT + "/stage/cafe", 200,
                    "{\"files\":[{\"path\":\"/store/one\",\"state\":\"STARTED\","
                    + "\"onDisk\":\"1\"}]}");

            assertTrue(tape.status(server.url("/store/one"), "cafe",
                    List.of(server.url("/store/one"))).get(0).online());
        }
    }

    @Test
    void saysWhichFilesTheAnswerNeverMentioned() throws IOException {
        try (MockTapeServer server = new MockTapeServer();
             TapeApi tape = new TapeApi(config())) {
            server.answering(ROOT + "/stage/cafe", 200,
                    "{\"files\":[{\"path\":\"/store/one\",\"state\":\"COMPLETED\"}]}");

            List<PrepareStatus> status = tape.status(server.url("/store/one"), "cafe",
                    List.of(server.url("/store/one"), server.url("/store/absent")));

            assertEquals(2, status.size());
            assertEquals("/store/absent", status.get(1).path());
            assertEquals("not part of this request", status.get(1).error());
            assertFalse(status.get(1).exists());
        }
    }

    @Test
    void readsARequestWhoseFilesAreTheWholeBody() throws IOException {
        try (MockTapeServer server = new MockTapeServer();
             TapeApi tape = new TapeApi(config())) {
            server.answering(ROOT + "/stage/cafe", 200,
                    "[{\"path\":\"/store/one\",\"state\":\"COMPLETED\"}]");

            assertTrue(tape.status(server.url("/store/one"), "cafe", List.of()).get(0).online());
        }
    }

    // -----------------------------------------------------------------
    // Withdrawing and releasing
    // -----------------------------------------------------------------

    @Test
    void cancelsSomeFilesAndWithdrawsTheWholeRequest() throws IOException {
        try (MockTapeServer server = new MockTapeServer();
             TapeApi tape = new TapeApi(config())) {
            server.answering(ROOT + "/stage/cafe/cancel", 200, "{}")
                    .answering(ROOT + "/stage/cafe", 204, null);

            tape.cancel(server.url("/store/one"), "cafe", List.of(server.url("/store/one")));
            tape.delete(server.url("/store/one"), "cafe");

            assertEquals(List.of("/store/one"), Json.array(Json.object(Json.parse(
                    server.call("POST", ROOT + "/stage/cafe/cancel").body())).get("paths")));
            assertEquals("DELETE", server.call("DELETE", ROOT + "/stage/cafe").method());
        }
    }

    @Test
    void releasesTheDiskCopiesTheRequestPinned() throws IOException {
        try (MockTapeServer server = new MockTapeServer();
             TapeApi tape = new TapeApi(config())) {
            server.answering(ROOT + "/release/cafe", 200, "{}");

            tape.release(server.url("/store/one"), "cafe",
                    List.of(server.url("/store/one"), server.url("/store/two")));

            assertEquals(List.of("/store/one", "/store/two"), Json.array(Json.object(Json.parse(
                    server.call("POST", ROOT + "/release/cafe").body())).get("paths")));
        }
    }

    // -----------------------------------------------------------------
    // Where the files are
    // -----------------------------------------------------------------

    @Test
    void readsTheLocalityOfEachFile() throws IOException {
        try (MockTapeServer server = new MockTapeServer();
             TapeApi tape = new TapeApi(config())) {
            server.answering(ROOT + "/archiveinfo", 200, """
                    [{"path":"/store/disk","locality":"ONLINE"},
                     {"path":"/store/tape","locality":"NEARLINE"},
                     {"path":"/store/both","locality":"ONLINE_AND_NEARLINE"},
                     {"path":"/store/gone","locality":"LOST"}]
                    """);

            List<PrepareStatus> where = tape.archiveInfo(List.of(
                    server.url("/store/disk"), server.url("/store/tape"),
                    server.url("/store/both"), server.url("/store/gone")));

            assertTrue(where.get(0).online());
            assertFalse(where.get(0).onTape());

            assertFalse(where.get(1).online());
            assertTrue(where.get(1).onTape());

            assertTrue(where.get(2).online(), "a compound locality is read in halves");
            assertTrue(where.get(2).onTape());

            assertFalse(where.get(3).exists());
            assertEquals("lost", where.get(3).error());
            assertEquals(List.of("/store/disk", "/store/tape", "/store/both", "/store/gone"),
                    Json.array(Json.object(Json.parse(
                            server.call("POST", ROOT + "/archiveinfo").body())).get("paths")));
        }
    }

    @Test
    void readsTheSpecificationsOwnVocabularyToo() throws IOException {
        try (MockTapeServer server = new MockTapeServer();
             TapeApi tape = new TapeApi(config())) {
            server.answering(ROOT + "/archiveinfo", 200,
                    "{\"responses\":[{\"path\":\"/store/one\",\"locality\":\"DISK_AND_TAPE\"}]}");

            PrepareStatus where = tape.archiveInfo(List.of(server.url("/store/one"))).get(0);
            assertTrue(where.online());
            assertTrue(where.onTape());
        }
    }

    // -----------------------------------------------------------------
    // When it goes wrong
    // -----------------------------------------------------------------

    @Test
    void refusesAnAnswerThatIsNotJson() throws IOException {
        try (MockTapeServer server = new MockTapeServer();
             TapeApi tape = new TapeApi(config())) {
            server.answering(ROOT + "/stage/cafe", 200, "<html>a proxy, not a storage element");

            XrdProtocolException e = assertThrows(XrdProtocolException.class,
                    () -> tape.status(server.url("/store/one"), "cafe", List.of()));
            assertTrue(e.getMessage().contains("did not answer with JSON"), e.getMessage());
        }
    }

    @Test
    void reportsWhatTheServerSaidWhenItRefuses() throws IOException {
        try (MockTapeServer server = new MockTapeServer();
             TapeApi tape = new TapeApi(config())) {
            server.answering(ROOT + "/stage", 403, "{\"message\":\"no\"}");

            XrdServerException e = assertThrows(XrdServerException.class,
                    () -> tape.stage(List.of(server.url("/store/one"))));
            assertTrue(e.getMessage().contains("403"), e.getMessage());
        }
    }

    @Test
    void carriesTheBearerTokenToTheApiAsWell() throws IOException {
        try (MockTapeServer server = new MockTapeServer();
             TapeApi tape = new TapeApi(config())) {
            server.answering(ROOT + "/stage", 201, "{\"requestId\":\"x\"}");
            tape.stage(List.of(server.url("/store/one")));
            assertEquals("Bearer s3cret",
                    server.call("POST", ROOT + "/stage").authorization());
        }
    }
}

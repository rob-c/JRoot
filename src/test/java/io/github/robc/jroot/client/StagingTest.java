package io.github.robc.jroot.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.wire.Types.PrepareStatus;
import io.github.robc.jroot.wire.XrdConst;

/** Staging over the binary protocol: the request, the query, the withdrawal. */
@Timeout(30)
class StagingTest {

    private static Config config() {
        return Config.defaults().withTls(Config.Tls.DISABLED).withAllowUnix(true);
    }

    private static MockXrootd.Request only(MockXrootd server, int opcode) {
        return server.requests().stream()
                .filter(request -> request.opcode() == opcode)
                .findFirst().orElseThrow();
    }

    @Test
    void asksForFilesToBeStagedAndKeepsTheHandle() throws IOException {
        try (MockXrootd server = new MockXrootd()) {
            server.on(XrdConst.kXR_prepare, MockXrootd.answering(request ->
                    MockXrootd.Reply.ok("7f3a")));
            try (XrdClient client = new XrdClient(config())) {
                assertEquals("7f3a", client.prepare(
                        List.of(server.url("/store/one"), server.url("/store/two")),
                        XrdConst.kXR_stage, 0));
            }
            MockXrootd.Request prepare = only(server, XrdConst.kXR_prepare);
            assertEquals("/store/one\n/store/two", prepare.text());
            assertEquals(XrdConst.kXR_stage, prepare.params()[0] & 0xFF);
        }
    }

    @Test
    void readsBackTheProgressOfEachFile() throws IOException {
        try (MockXrootd server = new MockXrootd()) {
            server.on(XrdConst.kXR_query, MockXrootd.answering(request ->
                    MockXrootd.Reply.ok("""
                            {"request_id":"7f3a","responses":[
                              {"path":"/store/one","path_exists":1,"on_tape":1,
                               "online":0,"requested":1,"has_reqid":1,
                               "req_time":"1700000000","error_text":"","state":"staging"},
                              {"path":"/store/two","path_exists":1,"on_tape":0,
                               "online":1,"requested":1,"has_reqid":1,
                               "req_time":"1700000000","error_text":"","state":"online"}]}""")));
            List<PrepareStatus> statuses;
            try (XrdClient client = new XrdClient(config())) {
                statuses = client.prepareStatus("7f3a",
                        List.of(server.url("/store/one"), server.url("/store/two")));
            }
            assertEquals(2, statuses.size());
            assertTrue(statuses.get(0).onTape());
            assertTrue(statuses.get(1).online());
            MockXrootd.Request query = only(server, XrdConst.kXR_query);
            assertEquals(XrdConst.kXR_QPrep, query.params()[1] & 0xFF);
            assertEquals("7f3a\n/store/one\n/store/two", query.text());
        }
    }

    @Test
    void tellsTheCallerAboutAFileTheServerLeftOut() throws IOException {
        try (MockXrootd server = new MockXrootd()) {
            server.on(XrdConst.kXR_query, MockXrootd.answering(request ->
                    MockXrootd.Reply.ok("{\"responses\":[{\"path\":\"/store/one\","
                            + "\"online\":1,\"path_exists\":1}]}")));
            try (XrdClient client = new XrdClient(config())) {
                List<PrepareStatus> statuses = client.prepareStatus("7f3a",
                        List.of(server.url("/store/one"), server.url("/store/gone")));
                assertTrue(statuses.get(0).online());
                assertFalse(statuses.get(1).exists());
                assertEquals("not part of this request", statuses.get(1).error());
            }
        }
    }

    @Test
    void staysOffTheWireWhenThereIsNothingToAskAbout() throws IOException {
        try (MockXrootd server = new MockXrootd()) {
            try (XrdClient client = new XrdClient(config())) {
                assertTrue(client.prepareStatus("7f3a", List.of()).isEmpty());
            }
            assertTrue(server.requests().isEmpty());
        }
    }

    @Test
    void withdrawsARequestByNamingItRatherThanItsFiles() throws IOException {
        try (MockXrootd server = new MockXrootd()) {
            server.on(XrdConst.kXR_prepare, MockXrootd.answering(request ->
                    MockXrootd.Reply.ok(new byte[0])));
            try (XrdClient client = new XrdClient(config())) {
                client.cancelPrepare(server.url("/store/one"), "7f3a");
            }
            MockXrootd.Request cancel = only(server, XrdConst.kXR_prepare);
            assertEquals("7f3a", cancel.text());
            assertEquals(XrdConst.kXR_cancel, cancel.params()[0] & 0xFF);
        }
    }
}

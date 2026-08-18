package io.github.robc.jroot.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.wire.Types.LocationInfo;
import io.github.robc.jroot.wire.XrdConst;

/**
 * A federation is a tree of redirectors, so one {@code kXR_locate} is a list
 * of places to ask rather than a list of replicas. These tests build the tree
 * out of real servers and check what comes back from walking it.
 */
@Timeout(30)
class DeepLocateTest {

    private static Config config() {
        return Config.defaults().withTls(Config.Tls.DISABLED).withAllowUnix(true);
    }

    private static String address(MockXrootd server) {
        return server.url("").substring("root://".length()).replace("/", "");
    }

    @Test
    void followsTheManagersDownToTheServersHoldingTheFile() throws IOException {
        try (MockXrootd site = new MockXrootd()) {
            site.on(XrdConst.kXR_locate, MockXrootd.answering(request ->
                    MockXrootd.Reply.ok("Sr[::1]:2094 Sw[::2]:2094")));
            try (MockXrootd top = new MockXrootd()) {
                top.on(XrdConst.kXR_locate, MockXrootd.answering(request ->
                        MockXrootd.Reply.ok("Mr" + address(site) + " Sr[::3]:3094")));

                try (XrdClient client = new XrdClient(config())) {
                    List<LocationInfo> found = client.deepLocate(top.url("/store/f.root"));

                    assertEquals(List.of("[::3]:3094", "[::1]:2094", "[::2]:2094"),
                            found.stream().map(LocationInfo::address).toList());
                    assertTrue(found.stream().noneMatch(LocationInfo::isManager));
                }
            }
        }
    }

    @Test
    void asksAManagerOnlyOnceHoweverManyPlacesNameIt() throws IOException {
        try (MockXrootd site = new MockXrootd()) {
            site.on(XrdConst.kXR_locate, MockXrootd.answering(request ->
                    MockXrootd.Reply.ok("Sr[::1]:2094")));
            try (MockXrootd top = new MockXrootd()) {
                String below = address(site);
                top.on(XrdConst.kXR_locate, MockXrootd.answering(request ->
                        MockXrootd.Reply.ok("Mr" + below + " Mr" + below)));

                try (XrdClient client = new XrdClient(config())) {
                    assertEquals(List.of("[::1]:2094"),
                            client.deepLocate(top.url("/store/f.root")).stream()
                                    .map(LocationInfo::address).toList());
                }
                assertEquals(1, site.requests().stream()
                        .filter(request -> request.opcode() == XrdConst.kXR_locate).count());
            }
        }
    }

    @Test
    void keepsTheReplicasItFoundWhenAManagerWillNotAnswer() throws IOException {
        try (MockXrootd top = new MockXrootd()) {
            // Port 1 is not a server, and never will be.
            top.on(XrdConst.kXR_locate, MockXrootd.answering(request ->
                    MockXrootd.Reply.ok("Mr127.0.0.1:1 Sr[::1]:2094")));
            try (XrdClient client = new XrdClient(config().withConnectTimeout(
                    java.time.Duration.ofSeconds(2)))) {
                assertEquals(List.of("[::1]:2094"),
                        client.deepLocate(top.url("/store/f.root")).stream()
                                .map(LocationInfo::address).toList());
            }
        }
    }

    @Test
    void aDataServerAnsweringWithItselfIsTheWholeAnswer() throws IOException {
        try (MockXrootd server = new MockXrootd()) {
            server.on(XrdConst.kXR_locate, MockXrootd.answering(request ->
                    MockXrootd.Reply.ok("Sw[::1]:1094")));
            try (XrdClient client = new XrdClient(config())) {
                List<LocationInfo> found = client.deepLocate(server.url("/store/f.root"));
                assertEquals(1, found.size());
                assertTrue(found.get(0).isWritable());
            }
        }
    }
}

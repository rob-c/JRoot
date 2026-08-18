package io.github.robc.jroot.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.wire.XrdConst;

/**
 * The token a client puts in its login: what a site's monitoring has to work
 * with, and what it must not be able to break.
 */
@Timeout(30)
class ClientIdTest {

    private static Map<String, String> fieldsOf(String token) {
        Map<String, String> fields = new HashMap<>();
        for (String part : token.split("&")) {
            int equals = part.indexOf('=');
            assertTrue(equals > 0, "every field is a pair: " + part);
            fields.put(part.substring(0, equals), part.substring(equals + 1));
        }
        return fields;
    }

    @Test
    void namesTheReleaseAndLeavesOutWhatNobodySet() {
        Map<String, String> fields = fieldsOf(ClientId.of(Config.defaults()));
        assertTrue(fields.containsKey("xrd.tz"), fields.toString());
        assertTrue(fields.get("xrd.rn").startsWith("jroot"), fields.toString());
        assertFalse(fields.containsKey("xrd.appname"), fields.toString());
        assertFalse(fields.containsKey("xrd.info"), fields.toString());
    }

    @Test
    void carriesTheApplicationNameAndTheFreeText() {
        Map<String, String> fields = fieldsOf(ClientId.of(Config.defaults()
                .withAppName("analysis").withClientInfo("run 12345")));
        assertEquals("analysis", fields.get("xrd.appname"));
        assertEquals("run_12345", fields.get("xrd.info"));
    }

    @Test
    void keepsTheTokenParsableWhateverTheCallerPutInIt() {
        String token = ClientId.of(Config.defaults()
                .withAppName("a&b=c?d").withClientInfo("one=two&three"));
        Map<String, String> fields = fieldsOf(token);
        assertEquals("abcd", fields.get("xrd.appname"));
        assertEquals("onetwothree", fields.get("xrd.info"));
    }

    @Test
    void sendsNoMoreThanTheReferenceClientDoes() {
        String longName = "abcdefghijklmnopqrstuvwxyz";
        String longInfo = "x".repeat(1000);
        Map<String, String> fields = fieldsOf(ClientId.of(Config.defaults()
                .withAppName(longName).withClientInfo(longInfo)));
        assertEquals(ClientId.MAX_APPNAME, fields.get("xrd.appname").length());
        assertEquals(ClientId.MAX_INFO, fields.get("xrd.info").length());
    }

    @Test
    void reportsAWholeNumberOfHoursFromGreenwich() {
        int hours = ClientId.timezone();
        assertTrue(hours >= -14 && hours <= 14, "hours west of UTC: " + hours);
    }

    @Test
    void trimsWhatItCannotSendRatherThanSendingIt() {
        assertEquals("", ClientId.clean(null, 8));
        assertEquals("", ClientId.clean("   ", 8));
        assertEquals("a_b", ClientId.clean("a b ", 8));
    }

    @Test
    void arrivesAtTheServerInTheLogin() throws IOException {
        try (MockXrootd server = new MockXrootd();
                XrdClient client = new XrdClient(Config.defaults()
                        .withTls(Config.Tls.DISABLED).withAppName("hammer"))) {
            client.connection(XrdUrl.parse(server.url("data")));
            String token = server.requests().stream()
                    .filter(request -> request.opcode() == XrdConst.kXR_login)
                    .map(request -> new String(request.payload(), StandardCharsets.UTF_8))
                    .findFirst().orElseThrow();
            assertTrue(token.contains("xrd.appname=hammer"), token);
            assertTrue(token.contains("xrd.rn=jroot"), token);
        }
    }
}

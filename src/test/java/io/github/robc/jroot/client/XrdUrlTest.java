package io.github.robc.jroot.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

import io.github.robc.jroot.XrdException;
import io.github.robc.jroot.wire.XrdConst;

/** URL parsing, including the shapes only xrootd uses. */
class XrdUrlTest {

    @Test
    void parsesTheOrdinaryForm() {
        XrdUrl url = XrdUrl.parse("root://door.example.org:1094//store/data/file.root");
        assertEquals("root", url.scheme());
        assertEquals("door.example.org", url.host());
        assertEquals(1094, url.port());
        assertEquals("/store/data/file.root", url.path());
        assertEquals("", url.cgi());
        assertFalse(url.requiresTls());
    }

    @Test
    void defaultsThePort() {
        assertEquals(XrdConst.DEFAULT_PORT, XrdUrl.parse("root://door//store/f").port());
    }

    @Test
    void keepsASingleSlashPathAsWritten() {
        // One slash is a path relative to the server's export, two is absolute;
        // both arrive at the server as one leading slash.
        assertEquals("/store/f", XrdUrl.parse("root://door/store/f").path());
        assertEquals("/store/f", XrdUrl.parse("root://door//store/f").path());
    }

    @Test
    void readsTheUserAndTheCgi() {
        XrdUrl url = XrdUrl.parse("root://rcurrie@door:1095//f?authz=Bearer%20abc&xrd.wantprot=gsi");
        assertEquals("rcurrie", url.user());
        assertEquals("door", url.host());
        assertEquals("authz=Bearer%20abc&xrd.wantprot=gsi", url.cgi());
        assertEquals("/f?authz=Bearer%20abc&xrd.wantprot=gsi", url.pathWithCgi());
        // Values stay percent-encoded: they go back on the wire as they came.
        assertEquals(Map.of("authz", "Bearer%20abc", "xrd.wantprot", "gsi"),
                url.cgiParameters());
    }

    @Test
    void parsesAMetamanagersListOfDoors() {
        XrdUrl url = XrdUrl.parse("root://one:1094,two:2094,[2001:db8::1]:3094//f");
        assertEquals(3, url.endpoints().size());
        assertEquals("one", url.endpoints().get(0).host());
        assertEquals(2094, url.endpoints().get(1).port());
        assertEquals("2001:db8::1", url.endpoints().get(2).host());
        assertEquals(3094, url.endpoints().get(2).port());
        assertEquals(url.endpoints().get(0), url.endpoint(), "the first is the one to try");
    }

    @Test
    void parsesABareIpv6Literal() {
        XrdUrl url = XrdUrl.parse("root://[2001:db8::1]//f");
        assertEquals("2001:db8::1", url.host());
        assertEquals(XrdConst.DEFAULT_PORT, url.port());
    }

    @Test
    void knowsWhichSchemesAreEncrypted() {
        assertTrue(XrdUrl.parse("roots://door//f").requiresTls());
        assertTrue(XrdUrl.parse("xroots://door//f").requiresTls());
        assertFalse(XrdUrl.parse("xroot://door//f").requiresTls());
        assertTrue(XrdUrl.isXrootd("ROOT"));
        assertFalse(XrdUrl.isXrootd("https"));
    }

    @Test
    void refusesWhatIsNotAnXrootdUrl() {
        assertThrows(XrdException.class, () -> XrdUrl.parse("/store/data/file.root"));
        assertThrows(XrdException.class, () -> XrdUrl.parse("https://host/f"));
        assertThrows(XrdException.class, () -> XrdUrl.parse("root:///store/f"));
        assertThrows(XrdException.class, () -> XrdUrl.parse("root://door:0//f"));
        assertThrows(XrdException.class, () -> XrdUrl.parse("root://door:nope//f"));
        assertThrows(XrdException.class, () -> XrdUrl.parse("root://[2001:db8::1//f"));
    }

    @Test
    void repointsAUrlAtTheServerARedirectNamed() {
        XrdUrl url = XrdUrl.parse("root://door//store/f?authz=abc");
        XrdUrl moved = url.at("pool7", 1095, true);
        assertEquals("roots", moved.scheme());
        assertEquals("pool7", moved.host());
        assertEquals(1095, moved.port());
        assertEquals("/store/f", moved.path());
        assertEquals("authz=abc", moved.cgi(), "the opaque data survives the move");
        assertEquals("/store/g", url.withPath("/store/g").path());
        assertEquals("t=1", url.withCgi("t=1").cgi());
        assertEquals("", url.withCgi(null).cgi());
    }

    @Test
    void keysAConnectionOnTheServerAlone() {
        XrdUrl one = XrdUrl.parse("root://door:1094//a");
        XrdUrl two = XrdUrl.parse("root://door:1094//b?authz=xyz");
        assertEquals(one.serverKey(), two.serverKey());
        assertFalse(one.serverKey().equals(
                XrdUrl.parse("roots://door:1094//a").serverKey()),
                "a TLS session is not the same session");
        assertFalse(one.serverKey().equals(
                XrdUrl.parse("root://rcurrie@door:1094//a").serverKey()),
                "a different user is a different login");
    }

    @Test
    void printsBackWhatItParsed() {
        assertEquals("root://one:1094,two:2094//store/f?t=1",
                XrdUrl.parse("root://one:1094,two:2094//store/f?t=1").toString());
        assertEquals("root://rcurrie@door:1094//store/f",
                XrdUrl.parse("root://rcurrie@door//store/f").toString());
    }

    @Test
    void pointsAtTheAddressALocateAnsweredWith() {
        XrdUrl url = XrdUrl.parse("root://redirector:1094//store/f?authz=abc");

        assertEquals("root://data.example:2094//store/f?authz=abc",
                url.at("data.example:2094").toString());

        XrdUrl six = url.at("[2001:db8::1]:2094");
        assertEquals("2001:db8::1", six.host());
        assertEquals(2094, six.port());

        // No port, and a port that is not a number, fall back to the default.
        assertEquals(XrdConst.DEFAULT_PORT, url.at("data.example").port());
        assertEquals("data.example", url.at("data.example").host());
        assertEquals(XrdConst.DEFAULT_PORT, url.at("data.example:not-a-port").port());
    }
}

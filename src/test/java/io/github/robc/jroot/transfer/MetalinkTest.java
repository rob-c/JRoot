package io.github.robc.jroot.transfer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import io.github.robc.jroot.XrdException;

/** The replica lists FTS and Rucio hand out in place of a source URL. */
class MetalinkTest {

    private static final String META4 = """
            <?xml version="1.0" encoding="UTF-8"?>
            <metalink xmlns="urn:ietf:params:xml:ns:metalink">
              <file name="/store/data/file.root">
                <size>1048576</size>
                <hash type="adler32">0034d81b</hash>
                <hash type="md5">d41d8cd98f00b204e9800998ecf8427e</hash>
                <url priority="1">root://one.example.org//store/data/file.root</url>
                <url priority="10">root://two.example.org//store/data/file.root</url>
                <url>https://three.example.org/store/data/file.root</url>
              </file>
            </metalink>
            """;

    @Test
    void readsAFileItsSizeItsChecksumAndItsReplicas() {
        Metalink.Entry entry = Metalink.parse(META4).get(0);
        assertEquals("/store/data/file.root", entry.name());
        assertEquals(1048576, entry.size());
        assertEquals("0034d81b", entry.checksums().get("adler32"));
        assertEquals(3, entry.replicas().size());
    }

    @Test
    void putsTheReplicaThePublisherPrefersFirst() {
        List<String> urls = Metalink.parse(META4).get(0).urls();
        assertEquals("root://one.example.org//store/data/file.root", urls.get(0));
        assertEquals("root://two.example.org//store/data/file.root", urls.get(1));
        // The one with no priority at all goes last, not first.
        assertEquals("https://three.example.org/store/data/file.root", urls.get(2));
    }

    @Test
    void prefersTheChecksumThisClientCanActuallyCheck() {
        assertEquals("adler32", Metalink.parse(META4).get(0).checksum().orElseThrow().getKey());
    }

    @Test
    void readsTheOlderVersionTooWhereAHigherPreferenceWon() {
        // Metalink 3 ordered replicas by preference out of 100, descending,
        // which is the opposite sense of metalink 4's priority.
        Metalink.Entry entry = Metalink.parse("""
                <metalink version="3.0" xmlns="http://www.metalinker.org/">
                  <files><file name="file.root">
                    <verification><hash type="md5">abc</hash></verification>
                    <resources>
                      <url type="http" preference="10">https://slow.example.org/f</url>
                      <url type="http" preference="90">https://fast.example.org/f</url>
                    </resources>
                  </file></files>
                </metalink>
                """).get(0);
        assertEquals(List.of("https://fast.example.org/f", "https://slow.example.org/f"),
                entry.urls());
        assertEquals("abc", entry.checksums().get("md5"));
        assertEquals(-1, entry.size());
    }

    @Test
    void takesADocumentWithNoNamespaceAtAll() {
        assertEquals(1, Metalink.parse("""
                <metalink><file name="f"><url>root://host//f</url></file></metalink>
                """).get(0).replicas().size());
    }

    @Test
    void namesAFileWithNoReplicaAsTheProblemItIs() {
        XrdException failure = assertThrows(XrdException.class, () -> Metalink.parse("""
                <metalink><file name="orphan.root"><size>10</size></file></metalink>
                """));
        assertTrue(failure.getMessage().contains("orphan.root"), failure.getMessage());
    }

    @Test
    void refusesADocumentThatIsNotOne() {
        assertThrows(XrdException.class, () -> Metalink.parse("<metalink></metalink>"));
        assertThrows(XrdException.class, () -> Metalink.parse("not xml at all"));
    }

    @Test
    void willNotFetchWhateverADocumentPointsAt() {
        // An entity declaration in a document from the network is an attempt
        // to read a local file, and the parser must not oblige it.
        assertThrows(XrdException.class, () -> Metalink.parse("""
                <?xml version="1.0"?>
                <!DOCTYPE metalink [<!ENTITY x SYSTEM "file:///etc/passwd">]>
                <metalink><file name="f"><url>&x;</url></file></metalink>
                """));
    }

    @Test
    void knowsOneWhenItSeesTheName() {
        assertTrue(Metalink.looksLikeOne("https://host/list.meta4"));
        assertTrue(Metalink.looksLikeOne("/tmp/LIST.METALINK"));
        assertTrue(Metalink.looksLikeOne("root://host//f.meta4?authz=abc"));
        assertFalse(Metalink.looksLikeOne("root://host//file.root"));
        assertFalse(Metalink.looksLikeOne(null));
    }
}

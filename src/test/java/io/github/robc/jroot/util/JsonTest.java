package io.github.robc.jroot.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.github.robc.jroot.XrdProtocolException;

/**
 * The JSON the two staging APIs speak.
 *
 * <p>The grammar is RFC 8259's, so the tests are the grammar's own edges:
 * escapes, nesting, the numbers a document may carry, and the malformed
 * inputs a reader has to refuse rather than half-read.
 */
class JsonTest {

    @Test
    void readsTheShapesADocumentIsMadeOf() {
        Object document = Json.parse("""
                {"id": "42", "count": 3, "ok": true, "gone": null,
                 "files": [{"path": "/a"}, {"path": "/b"}]}
                """);
        assertEquals("42", Json.text(document, "id"));
        assertEquals(3, Json.integer(document, "count", -1));
        assertTrue(Json.flag(document, "ok"));
        assertEquals("", Json.text(document, "gone"));
        assertEquals(2, Json.array(Json.object(document).get("files")).size());
        assertEquals("/b", Json.text(Json.array(Json.object(document).get("files")).get(1),
                "path"));
    }

    @Test
    void readsAnArrayAsAWholeDocument() {
        List<Object> items = Json.array(Json.parse("[1, \"two\", false, null, []]"));
        assertEquals(5, items.size());
        assertEquals(1.0, items.get(0));
        assertEquals("two", items.get(1));
        assertEquals(Boolean.FALSE, items.get(2));
        assertEquals(null, items.get(3));
        assertEquals(List.of(), items.get(4));
    }

    @Test
    void keepsTheOrderTheDocumentHad() {
        Map<String, Object> members = Json.object(Json.parse("{\"z\":1,\"a\":2,\"m\":3}"));
        assertEquals(List.of("z", "a", "m"), List.copyOf(members.keySet()));
    }

    @Test
    void understandsEveryEscapeTheGrammarHas() {
        assertEquals("\" \\ / \b \f \n \r \t \u00e9",
                Json.object(Json.parse("{\"s\":\"\\\" \\\\ \\/ \\b \\f \\n \\r \\t \\u00e9\"}"))
                        .get("s"));
    }

    @Test
    void readsTheNumbersADocumentMayCarry() {
        Object document = Json.parse("{\"a\":-1,\"b\":1.5e3,\"c\":0,\"d\":1668516326}");
        assertEquals(-1, Json.integer(document, "a", 0));
        assertEquals(1500, Json.integer(document, "b", 0));
        assertEquals(0, Json.integer(document, "c", -1));
        assertEquals(1668516326L, Json.integer(document, "d", 0));
        assertEquals("1668516326", Json.text(document, "d"), "no exponent, no decimal point");
    }

    @Test
    void takesAYesHoweverTheServerSpeltIt() {
        Object document = Json.parse(
                "{\"a\":true,\"b\":1,\"c\":\"1\",\"d\":\"TRUE\",\"e\":\"yes\","
                + "\"f\":false,\"g\":0,\"h\":\"no\",\"i\":\"\"}");
        for (String key : List.of("a", "b", "c", "d", "e")) {
            assertTrue(Json.flag(document, key), key);
        }
        for (String key : List.of("f", "g", "h", "i", "absent")) {
            assertFalse(Json.flag(document, key), key);
        }
    }

    @Test
    void writesWhatItCanReadBack() {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("paths", List.of("/a", "/b"));
        document.put("count", 2);
        document.put("ok", true);
        document.put("none", null);
        String text = Json.write(document);
        assertEquals("{\"paths\":[\"/a\",\"/b\"],\"count\":2,\"ok\":true,\"none\":null}", text);
        assertEquals("/b", Json.array(Json.object(Json.parse(text)).get("paths")).get(1));
    }

    @Test
    void quotesWhatWouldOtherwiseEndTheString() {
        assertEquals("{\"k\":\"a\\\"b\\\\c\\nd\\u0001\"}",
                Json.write(Map.of("k", "a\"b\\c\nd\u0001")));
    }

    @Test
    void refusesADocumentThatIsNotOne() {
        for (String bad : List.of("", "   ", "{", "{\"a\"}", "{\"a\":}", "[1,", "[1 2]",
                "tru", "{\"a\":1}{", "\"unterminated", "{\"a\":\"\\q\"}", "{\"a\":\"\\uZZZZ\"}")) {
            assertThrows(XrdProtocolException.class, () -> Json.parse(bad), bad);
        }
    }

    @Test
    void treatsAnythingThatIsNotAnObjectAsAnEmptyOne() {
        assertEquals(Map.of(), Json.object(Json.parse("[1]")));
        assertEquals(List.of(), Json.array(Json.parse("{}")));
        assertEquals("", Json.text(Json.parse("[]"), "path"));
        assertEquals(7, Json.integer(Json.parse("{\"a\":\"x\"}"), "a", 7));
    }
}

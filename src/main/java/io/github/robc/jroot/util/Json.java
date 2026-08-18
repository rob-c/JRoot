package io.github.robc.jroot.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import io.github.robc.jroot.XrdProtocolException;

/**
 * Just enough JSON for the two places the protocols use it.
 *
 * <p>{@code kXR_query} answers a prepare query with a JSON document, and the
 * WLCG Tape REST API is JSON throughout. Both are small, both are read rather
 * than round-tripped, and this library has no dependencies — so this is a
 * reader and a writer for the grammar in RFC 8259 and nothing beyond it.
 *
 * <p>Values come back as the obvious Java types: {@link Map} for an object,
 * preserving the order the document had; {@link List} for an array;
 * {@link String}, {@link Double}, {@link Boolean} and {@code null} for the
 * rest. Numbers are all doubles because JSON has one number type and nothing
 * here counts on more; {@link #integer} is where a caller wants a long back.
 */
public final class Json {

    private final String text;
    private int at;

    private Json(String text) {
        this.text = text;
    }

    /** Parse a whole document. Trailing content is an error, not a suffix. */
    public static Object parse(String text) {
        Json json = new Json(text == null ? "" : text);
        json.space();
        if (json.at >= json.text.length()) {
            throw json.fail("a document with nothing in it");
        }
        Object value = json.value();
        json.space();
        if (json.at < json.text.length()) {
            throw json.fail("trailing content");
        }
        return value;
    }

    // -----------------------------------------------------------------
    // Reading what a document holds
    // -----------------------------------------------------------------

    /** {@code value} as an object, or an empty one when it is anything else. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> object(Object value) {
        return value instanceof Map ? (Map<String, Object>) value : Map.of();
    }

    /** {@code value} as an array, or an empty one when it is anything else. */
    @SuppressWarnings("unchecked")
    public static List<Object> array(Object value) {
        return value instanceof List ? (List<Object>) value : List.of();
    }

    /** One member as text; a number or a boolean is rendered rather than lost. */
    public static String text(Object document, String key) {
        Object value = object(document).get(key);
        if (value == null) {
            return "";
        }
        if (value instanceof Double number && number == Math.rint(number)
                && !number.isInfinite()) {
            return String.valueOf(number.longValue());
        }
        return String.valueOf(value);
    }

    /**
     * One member as a boolean, however the server spelt it. Implementations
     * have written these as {@code true}, as {@code 1} and as {@code "1"},
     * and all three mean yes; a client that understood only one would report
     * a staged file as still on tape.
     */
    public static boolean flag(Object document, String key) {
        Object value = object(document).get(key);
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof Double number) {
            return number != 0;
        }
        if (value instanceof String word) {
            String lower = word.strip().toLowerCase();
            return lower.equals("1") || lower.equals("true") || lower.equals("yes");
        }
        return false;
    }

    /** One member as a whole number, or {@code fallback} when it is not one. */
    public static long integer(Object document, String key, long fallback) {
        Object value = object(document).get(key);
        if (value instanceof Double number && !number.isNaN() && !number.isInfinite()) {
            return number.longValue();
        }
        if (value instanceof String digits) {
            try {
                return Long.parseLong(digits.strip());
            } catch (NumberFormatException e) {
                return fallback;
            }
        }
        return fallback;
    }

    // -----------------------------------------------------------------
    // Writing one out
    // -----------------------------------------------------------------

    /** Render a value built from maps, lists, strings, numbers and booleans. */
    public static String write(Object value) {
        StringBuilder out = new StringBuilder();
        render(value, out);
        return out.toString();
    }

    private static void render(Object value, StringBuilder out) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof Map<?, ?> members) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : members.entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                quote(String.valueOf(entry.getKey()), out);
                out.append(':');
                render(entry.getValue(), out);
            }
            out.append('}');
        } else if (value instanceof Iterable<?> items) {
            out.append('[');
            boolean first = true;
            for (Object item : items) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                render(item, out);
            }
            out.append(']');
        } else if (value instanceof Boolean || value instanceof Number) {
            out.append(value);
        } else {
            quote(String.valueOf(value), out);
        }
    }

    private static void quote(String value, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    // -----------------------------------------------------------------
    // The grammar
    // -----------------------------------------------------------------

    private Object value() {
        space();
        char c = peek();
        return switch (c) {
            case '{' -> members();
            case '[' -> items();
            case '"' -> string();
            case 't' -> literal("true", Boolean.TRUE);
            case 'f' -> literal("false", Boolean.FALSE);
            case 'n' -> literal("null", null);
            default -> number();
        };
    }

    private Map<String, Object> members() {
        Map<String, Object> out = new LinkedHashMap<>();
        expect('{');
        space();
        if (peek() == '}') {
            at++;
            return out;
        }
        while (true) {
            space();
            String key = string();
            space();
            expect(':');
            out.put(key, value());
            space();
            char c = next();
            if (c == '}') {
                return out;
            }
            if (c != ',') {
                throw fail("a comma or a closing brace");
            }
        }
    }

    private List<Object> items() {
        List<Object> out = new ArrayList<>();
        expect('[');
        space();
        if (peek() == ']') {
            at++;
            return out;
        }
        while (true) {
            out.add(value());
            space();
            char c = next();
            if (c == ']') {
                return out;
            }
            if (c != ',') {
                throw fail("a comma or a closing bracket");
            }
        }
    }

    private String string() {
        expect('"');
        StringBuilder out = new StringBuilder();
        while (true) {
            char c = next();
            if (c == '"') {
                return out.toString();
            }
            if (c != '\\') {
                out.append(c);
                continue;
            }
            char escape = next();
            switch (escape) {
                case '"', '\\', '/' -> out.append(escape);
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'u' -> {
                    if (at + 4 > text.length()) {
                        throw fail("four hexadecimal digits");
                    }
                    try {
                        out.append((char) Integer.parseInt(text.substring(at, at + 4), 16));
                    } catch (NumberFormatException e) {
                        throw fail("four hexadecimal digits");
                    }
                    at += 4;
                }
                default -> throw fail("a known escape, not \\" + escape);
            }
        }
    }

    private Double number() {
        int from = at;
        while (at < text.length() && "+-.eE0123456789".indexOf(text.charAt(at)) >= 0) {
            at++;
        }
        try {
            return Double.valueOf(text.substring(from, at));
        } catch (NumberFormatException e) {
            throw fail("a value");
        }
    }

    private Object literal(String word, Object value) {
        if (!text.startsWith(word, at)) {
            throw fail(word);
        }
        at += word.length();
        return value;
    }

    private void space() {
        while (at < text.length() && Character.isWhitespace(text.charAt(at))) {
            at++;
        }
    }

    private char peek() {
        if (at >= text.length()) {
            throw fail("a value");
        }
        return text.charAt(at);
    }

    private char next() {
        char c = peek();
        at++;
        return c;
    }

    private void expect(char c) {
        if (next() != c) {
            at--;
            throw fail(String.valueOf(c));
        }
    }

    private XrdProtocolException fail(String wanted) {
        String where = text.substring(Math.max(0, at - 20), Math.min(text.length(), at + 20));
        return new XrdProtocolException("malformed JSON at offset " + at + ": expected "
                + wanted + ", near \"" + where + "\"");
    }
}

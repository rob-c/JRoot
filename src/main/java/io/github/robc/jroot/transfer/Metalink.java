package io.github.robc.jroot.transfer;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import io.github.robc.jroot.XrdException;
import io.github.robc.jroot.util.Xml;

/**
 * A metalink: one logical file, and every replica of it.
 *
 * <p>This is how a copy learns there is more than one place to read from
 * without asking a redirector — FTS and Rucio hand out {@code .meta4}
 * documents naming every replica of a dataset file, with its size and its
 * checksum, and {@code xrdcp} will take one in place of a source URL. Given
 * that list, {@link Transfer} can pull chunks from several at once and drop
 * one that fails without giving up on the copy.
 *
 * <p>Both versions in the field are read: metalink 4 (RFC 5854, where the
 * replicas are {@code <url>} children of {@code <file>}) and metalink 3
 * (where they sit under {@code <resources>}). The elements are found by
 * local name, so a document is free to bind the namespace where it likes,
 * or to leave it off, which plenty do.
 */
public final class Metalink {

    /** One replica, and how much the publisher wants it used. */
    public record Replica(String url, int priority) {}

    /**
     * One file: where it lives, how big it should be, and what it should
     * checksum to. {@code size} is negative when the document does not say.
     */
    public record Entry(String name, long size, Map<String, String> checksums,
                        List<Replica> replicas) {

        /** The replicas, most-preferred first. A lower priority wins. */
        public List<String> urls() {
            return replicas.stream().sorted(Comparator.comparingInt(Replica::priority))
                    .map(Replica::url).toList();
        }

        /** The checksum the publisher gave, in this client's order of preference. */
        public java.util.Optional<Map.Entry<String, String>> checksum() {
            for (String algorithm : Checksum.ALGORITHMS) {
                String value = checksums.get(algorithm);
                if (value != null && !value.isBlank()) {
                    return java.util.Optional.of(Map.entry(algorithm, value));
                }
            }
            return checksums.entrySet().stream().findFirst();
        }
    }

    /** Metalink's own default when a {@code <url>} states no priority. */
    static final int DEFAULT_PRIORITY = 999999;

    private Metalink() {
    }

    /** Whether a name looks like a metalink rather than a file to copy. */
    public static boolean looksLikeOne(String url) {
        String path = url == null ? "" : url.toLowerCase(java.util.Locale.ROOT);
        int query = path.indexOf('?');
        if (query >= 0) {
            path = path.substring(0, query);
        }
        return path.endsWith(".meta4") || path.endsWith(".metalink");
    }

    public static List<Entry> parse(byte[] body) {
        Document document = Xml.parse(body, "the metalink");
        Element root = document.getDocumentElement();
        if (root == null) {
            throw new XrdException("the metalink has no document element");
        }
        List<Entry> files = new ArrayList<>();
        for (Element file : Xml.descendants(root, "file")) {
            files.add(entry(file));
        }
        if (files.isEmpty()) {
            throw new XrdException("the metalink names no files");
        }
        return files;
    }

    public static List<Entry> parse(String body) {
        return parse(body.getBytes(StandardCharsets.UTF_8));
    }

    private static Entry entry(Element file) {
        String name = file.getAttribute("name").strip();
        long size = number(Xml.text(Xml.child(file, "size")));
        Map<String, String> checksums = new LinkedHashMap<>();
        for (Element hash : Xml.descendants(file, "hash")) {
            // Metalink 4 spells it type=, metalink 3 spelt it hash type= too,
            // but some writers use name=. Take whichever is there.
            String algorithm = hash.getAttribute("type").isBlank()
                    ? hash.getAttribute("name") : hash.getAttribute("type");
            if (!algorithm.isBlank()) {
                checksums.putIfAbsent(Checksum.normalise(algorithm), Xml.text(hash));
            }
        }
        List<Replica> replicas = new ArrayList<>();
        for (Element url : Xml.descendants(file, "url")) {
            String where = Xml.text(url);
            if (where.isEmpty()) {
                continue;
            }
            replicas.add(new Replica(where, priority(url)));
        }
        if (replicas.isEmpty()) {
            throw new XrdException("the metalink names " + (name.isEmpty() ? "a file" : name)
                    + " but no replica of it");
        }
        return new Entry(name, size, Map.copyOf(checksums), List.copyOf(replicas));
    }

    /**
     * Metalink 4 orders replicas by {@code priority}, ascending; metalink 3
     * ordered them by {@code preference}, descending, out of 100. Both are
     * read into the ascending sense, so one comparator serves.
     */
    private static int priority(Element url) {
        String priority = url.getAttribute("priority").strip();
        if (!priority.isEmpty()) {
            long value = number(priority);
            return value < 0 ? DEFAULT_PRIORITY : (int) Math.min(value, DEFAULT_PRIORITY);
        }
        String preference = url.getAttribute("preference").strip();
        if (!preference.isEmpty()) {
            long value = number(preference);
            return value < 0 ? DEFAULT_PRIORITY : (int) Math.max(0, 100 - value);
        }
        return DEFAULT_PRIORITY;
    }

    private static long number(String text) {
        try {
            return text.isEmpty() ? -1 : Long.parseLong(text.strip());
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}

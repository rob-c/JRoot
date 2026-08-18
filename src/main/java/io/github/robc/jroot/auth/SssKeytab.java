package io.github.robc.jroot.auth;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.github.robc.jroot.XrdAuthException;

/**
 * The keytab {@code sss} draws its shared secrets from — the file
 * {@code xrdsssadmin} writes, one key per line.
 *
 * <p>A line is a format version, {@code 0} or {@code 1}, then space-separated
 * {@code <tag>:<value>} fields: {@code k} the secret in hex, {@code N} its
 * numeric id, {@code n} its name, {@code u} and {@code g} the user and group
 * it maps to, {@code e} an expiry as seconds since the Unix epoch. Anything
 * from a {@code #} onwards is a comment.
 *
 * <p>A keytab holds secrets in the clear, so one that group or others can
 * read is refused rather than used. That refusal is the whole security model:
 * the file's permissions are what stands between a shared secret and everyone
 * with an account on the machine.
 */
public final class SssKeytab {

    private SssKeytab() {}

    /** One usable key. The secret is the Blowfish key, not a password. */
    public record Key(long id, byte[] secret, String name, String user, String group,
                      long expires) {

        public boolean isExpired() {
            return expires != 0 && expires <= Instant.now().getEpochSecond();
        }

        @Override
        public String toString() {
            return "SssKeytab.Key[id=" + id + ", name=" + name + ", secret=<redacted>]";
        }
    }

    /** Where the C client looks: {@code $XrdSecSSSKT}, {@code $XrdSecsssKT},
     *  then {@code ~/.xrd/sss.keytab}. */
    public static Path defaultPath() {
        for (String variable : new String[] {"XrdSecSSSKT", "XrdSecsssKT"}) {
            String value = System.getenv(variable);
            if (value != null && !value.isBlank()) {
                return Path.of(value);
            }
        }
        return Path.of(System.getProperty("user.home", "/tmp"), ".xrd", "sss.keytab");
    }

    /**
     * Every unexpired key in {@code path}, in file order.
     *
     * @throws XrdAuthException if the file is readable by anyone but its owner
     */
    public static List<Key> read(Path path) {
        return read(path, false);
    }

    /** As {@link #read(Path)}, but {@code includeExpired} keeps the keys that
     *  have run out — for reporting on a keytab, never for authenticating. */
    public static List<Key> read(Path path, boolean includeExpired) {
        requirePrivate(path);
        List<Key> keys = new ArrayList<>();
        try {
            for (String raw : Files.readAllLines(path, StandardCharsets.UTF_8)) {
                Key key = parse(raw);
                if (key != null && (includeExpired || !key.isExpired())) {
                    keys.add(key);
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return keys;
    }

    /** One line, or null when it is blank, a comment, or carries no secret. */
    private static Key parse(String raw) {
        String line = raw.strip();
        if (line.isEmpty() || line.startsWith("#")) {
            return null;
        }
        String[] fields = line.split("\\s+");
        if (!fields[0].equals("0") && !fields[0].equals("1")) {
            return null;
        }
        Map<Character, String> attributes = new HashMap<>();
        for (int i = 1; i < fields.length; i++) {
            if (fields[i].startsWith("#")) {
                break;
            }
            if (fields[i].length() > 1 && fields[i].charAt(1) == ':') {
                attributes.put(fields[i].charAt(0), fields[i].substring(2));
            }
        }
        byte[] secret = unhex(attributes.get('k'));
        if (secret.length == 0) {
            return null;
        }
        return new Key(number(attributes.get('N'), -1), secret,
                attributes.getOrDefault('n', ""), attributes.getOrDefault('u', ""),
                attributes.getOrDefault('g', ""), number(attributes.get('e'), 0));
    }

    /**
     * The permission check the C implementation makes, and for the same
     * reason: a secret every local account can read authenticates every local
     * account. Where the filesystem has no POSIX permissions there is nothing
     * to check and nothing to refuse.
     */
    private static void requirePrivate(Path path) {
        Set<PosixFilePermission> permissions;
        try {
            permissions = Files.getPosixFilePermissions(path);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (UnsupportedOperationException e) {
            return;
        }
        for (PosixFilePermission permission : permissions) {
            if (!permission.name().startsWith("OWNER")) {
                throw new XrdAuthException(path + " is readable by group or others;"
                        + " an SSS keytab holds cleartext secrets and must be mode 0600");
            }
        }
    }

    private static long number(String value, long fallback) {
        try {
            return value == null ? fallback : Long.parseLong(value.strip());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static byte[] unhex(String value) {
        if (value == null || value.isEmpty() || (value.length() & 1) != 0) {
            return new byte[0];
        }
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int high = Character.digit(value.charAt(2 * i), 16);
            int low = Character.digit(value.charAt(2 * i + 1), 16);
            if (high < 0 || low < 0) {
                return new byte[0];
            }
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }
}

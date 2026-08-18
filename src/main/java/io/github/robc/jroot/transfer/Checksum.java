package io.github.robc.jroot.transfer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.zip.Adler32;
import java.util.zip.CRC32;
import java.util.zip.CRC32C;

import io.github.robc.jroot.XrdException;

/**
 * The checksums storage elements name files by, computed here rather than
 * asked for.
 *
 * <p>A server will compute one on request — {@code kXR_query} with
 * {@code kXR_Qcksum} over the binary protocol, {@code Want-Digest} over HTTP
 * — but that only ever proves the server agrees with itself. A copy is only
 * verified end to end if one end of it was computed by the client, over the
 * bytes it actually holds, which is what this is for.
 *
 * <p>The algorithms are the ones WLCG storage carries: {@code adler32} above
 * all, which is why it is the default everywhere here, then {@code crc32},
 * {@code crc32c}, and the message digests.
 *
 * <p>Values are lowercase hex, the running sums zero-padded to eight digits.
 * They are also compared leniently, because implementations disagree about
 * that padding and a copy must not fail over a leading zero.
 */
public final class Checksum {

    /** What a caller gets when nothing said otherwise. */
    public static final String DEFAULT = "adler32";

    /** The names this understands, in the order a server is asked for them. */
    public static final List<String> ALGORITHMS =
            List.of("adler32", "crc32c", "crc32", "md5", "sha1", "sha256", "sha512");

    private static final int BLOCK = 1 << 20;

    private final String algorithm;
    private final java.util.zip.Checksum running;
    private final MessageDigest digest;

    private Checksum(String algorithm, java.util.zip.Checksum running, MessageDigest digest) {
        this.algorithm = algorithm;
        this.running = running;
        this.digest = digest;
    }

    /** A running sum of {@code algorithm}, fed with {@link #update}. */
    public static Checksum of(String algorithm) {
        String name = normalise(algorithm);
        return switch (name) {
            case "adler32" -> new Checksum(name, new Adler32(), null);
            case "crc32" -> new Checksum(name, new CRC32(), null);
            case "crc32c" -> new Checksum(name, new CRC32C(), null);
            default -> new Checksum(name, null, messageDigest(name));
        };
    }

    /** Whether this client can compute {@code algorithm} itself. */
    public static boolean supports(String algorithm) {
        String name = normalise(algorithm);
        if (ALGORITHMS.contains(name)) {
            return true;
        }
        try {
            MessageDigest.getInstance(javaName(name));
            return true;
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }

    public String algorithm() {
        return algorithm;
    }

    public Checksum update(byte[] data) {
        return update(data, 0, data.length);
    }

    public Checksum update(byte[] data, int offset, int length) {
        if (running != null) {
            running.update(data, offset, length);
        } else {
            digest.update(data, offset, length);
        }
        return this;
    }

    /** The value so far, as the storage element would write it. */
    public String value() {
        if (running != null) {
            return String.format("%08x", running.getValue());
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    // -----------------------------------------------------------------
    // Whole things
    // -----------------------------------------------------------------

    public static String of(String algorithm, Path path) {
        try (InputStream in = Files.newInputStream(path)) {
            return of(algorithm, in);
        } catch (IOException e) {
            throw new XrdException("cannot read " + path + " to checksum it: "
                    + e.getMessage(), e);
        }
    }

    public static String of(String algorithm, InputStream in) throws IOException {
        Checksum sum = of(algorithm);
        byte[] block = new byte[BLOCK];
        for (int read = in.read(block); read >= 0; read = in.read(block)) {
            sum.update(block, 0, read);
        }
        return sum.value();
    }

    /**
     * Read {@code source} through and checksum it. This is the expensive way
     * to learn a remote file's sum and the only way to learn it honestly:
     * every byte crosses the wire.
     */
    public static String of(String algorithm, Source source) {
        Checksum sum = of(algorithm);
        long size = source.size();
        for (long at = 0; size < 0 || at < size; ) {
            int want = size < 0 ? BLOCK : (int) Math.min(BLOCK, size - at);
            byte[] block = source.read(at, want);
            if (block.length == 0) {
                break;
            }
            sum.update(block);
            at += block.length;
        }
        return sum.value();
    }

    // -----------------------------------------------------------------
    // Comparing what two ends said
    // -----------------------------------------------------------------

    /**
     * Whether two servers named the same file.
     *
     * <p>Leniently: case is ignored, and so are leading zeros, because
     * implementations disagree about whether {@code adler32} is eight digits
     * or as few as it takes — dCache writes {@code 0034d81b} where XRootD
     * writes {@code 34d81b} — and a copy that failed over that would be
     * failing over formatting rather than over data.
     */
    public static boolean same(String left, String right) {
        String a = trim(left);
        String b = trim(right);
        return !a.isEmpty() && a.equals(b);
    }

    private static String trim(String value) {
        if (value == null) {
            return "";
        }
        String hex = value.strip().toLowerCase(Locale.ROOT);
        int at = 0;
        while (at < hex.length() - 1 && hex.charAt(at) == '0') {
            at++;
        }
        return hex.substring(at);
    }

    /** A name as the protocols spell it: lowercase, and {@code -} is nothing. */
    public static String normalise(String algorithm) {
        if (algorithm == null || algorithm.isBlank()) {
            return DEFAULT;
        }
        return algorithm.strip().toLowerCase(Locale.ROOT).replace("-", "");
    }

    private static MessageDigest messageDigest(String name) {
        try {
            return MessageDigest.getInstance(javaName(name));
        } catch (NoSuchAlgorithmException e) {
            throw new XrdException("this client cannot compute " + name
                    + "; it knows " + String.join(", ", ALGORITHMS), e);
        }
    }

    /** {@code sha256} on the wire is {@code SHA-256} to the JDK. */
    private static String javaName(String name) {
        if (name.startsWith("sha") && name.length() > 3) {
            return "SHA-" + name.substring(3);
        }
        return name.toUpperCase(Locale.ROOT);
    }

    @Override
    public String toString() {
        return "Checksum[" + algorithm + "]";
    }
}

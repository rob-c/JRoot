package io.github.robc.jroot.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import io.github.robc.jroot.XrdAuthException;
import io.github.robc.jroot.util.Posix;

/**
 * {@code ztn} — WLCG bearer tokens and SciTokens. The credential blob is
 * {@code "ztn\0<token>"}; discovery follows the WLCG Bearer Token Discovery
 * specification, which is what the C client does too: an explicit token,
 * then {@code $BEARER_TOKEN}, then {@code $BEARER_TOKEN_FILE}, then
 * {@code $XDG_RUNTIME_DIR/bt_u$UID}, then {@code /tmp/bt_u$UID}.
 */
public final class TokenCredential implements Credential {

    private final String token;
    private final Instant expiry;

    public TokenCredential(String token) {
        this.token = token.strip();
        this.expiry = expiryOf(this.token).orElse(null);
    }

    @Override
    public String name() {
        return "ztn";
    }

    @Override
    public byte[] initial() {
        if (expiry != null && !expiry.isAfter(Instant.now())) {
            throw new XrdAuthException("the bearer token expired at " + expiry);
        }
        byte[] raw = token.getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[4 + raw.length];
        System.arraycopy("ztn\0".getBytes(StandardCharsets.US_ASCII), 0, out, 0, 4);
        System.arraycopy(raw, 0, out, 4, raw.length);
        return out;
    }

    public String token() {
        return token;
    }

    public Optional<Instant> expiry() {
        return Optional.ofNullable(expiry);
    }

    /** The paths bearer-token discovery looks in, in order. */
    public static List<Path> searchPath() {
        List<Path> paths = new ArrayList<>();
        String file = System.getenv("BEARER_TOKEN_FILE");
        if (file != null && !file.isBlank()) {
            paths.add(Path.of(file));
        }
        String runtime = System.getenv("XDG_RUNTIME_DIR");
        int uid = Posix.uid();
        if (runtime != null && !runtime.isBlank() && uid >= 0) {
            paths.add(Path.of(runtime, "bt_u" + uid));
        }
        if (uid >= 0) {
            paths.add(Path.of("/tmp/bt_u" + uid));
        }
        return paths;
    }

    /** Locate a bearer token, or empty if there is not one to be had. */
    public static Optional<String> discover() {
        String env = System.getenv("BEARER_TOKEN");
        if (env != null && !env.isBlank()) {
            return Optional.of(env.strip());
        }
        for (Path path : searchPath()) {
            try {
                String content = Files.readString(path).strip();
                if (!content.isEmpty()) {
                    return Optional.of(content);
                }
            } catch (IOException | RuntimeException e) {
                // Absent or unreadable: the next candidate is the answer.
            }
        }
        return Optional.empty();
    }

    /**
     * Build a token credential for a server's {@code ztn} offer, or empty
     * when there is no token. The offer's {@code <lifetime>:<maxsize>:}
     * parameters are checked here so a token that would be refused never
     * crosses the wire.
     */
    public static Optional<TokenCredential> available(SecurityOffer offer, String token) {
        String value = token != null && !token.isBlank()
                ? token.strip() : discover().orElse(null);
        if (value == null) {
            return Optional.empty();
        }
        long[] limits = requirements(offer.params());
        if (limits[1] > 0 && value.length() > limits[1]) {
            throw new XrdAuthException("the bearer token is " + value.length()
                    + " bytes and the server accepts at most " + limits[1]);
        }
        TokenCredential credential = new TokenCredential(value);
        if (limits[0] > 0 && credential.expiry != null) {
            long left = credential.expiry.getEpochSecond() - Instant.now().getEpochSecond();
            if (left < limits[0]) {
                throw new XrdAuthException("the bearer token expires in " + Math.max(left, 0)
                        + "s and the server wants " + limits[0] + "s of life left in it");
            }
        }
        return Optional.of(credential);
    }

    /**
     * The server's {@code <lifetime>:<maxsize>:} offer parameters, zero when
     * unstated. Anything unparseable — old servers sent version strings — is
     * read as no requirement rather than refused: these parameters exist
     * only to fail sooner than the server would.
     */
    private static long[] requirements(String params) {
        String[] parts = params.split(":");
        long[] out = new long[2];
        for (int i = 0; i < 2 && i < parts.length; i++) {
            try {
                out[i] = Long.parseLong(parts[i].strip());
            } catch (NumberFormatException e) {
                return new long[2];
            }
        }
        return out;
    }

    /**
     * The {@code exp} claim of a JWT, without verifying the signature.
     * Verification is the server's job; the client reads the expiry so it
     * can fail with a sentence instead of a 3010 from the far end.
     */
    public static Optional<Instant> expiryOf(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            return Optional.empty();
        }
        String claims;
        try {
            claims = new String(Base64.getUrlDecoder().decode(padded(parts[1])),
                    StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        // A hand-rolled scan rather than a JSON parser: this library has no
        // dependencies, and "exp" is a bare number in every JWT there is.
        int at = claims.indexOf("\"exp\"");
        if (at < 0) {
            return Optional.empty();
        }
        int start = claims.indexOf(':', at);
        if (start < 0) {
            return Optional.empty();
        }
        StringBuilder digits = new StringBuilder();
        for (int i = start + 1; i < claims.length(); i++) {
            char c = claims.charAt(i);
            if (Character.isDigit(c)) {
                digits.append(c);
            } else if (!digits.isEmpty() || !(c == ' ' || c == '"')) {
                break;
            }
        }
        try {
            return digits.isEmpty() ? Optional.empty()
                    : Optional.of(Instant.ofEpochSecond(Long.parseLong(digits.toString())));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }

    private static String padded(String base64) {
        int pad = (4 - base64.length() % 4) % 4;
        return base64 + "=".repeat(pad);
    }

    @Override
    public String toString() {
        return "TokenCredential[len=" + token.length() + ", token=<redacted>]";
    }
}

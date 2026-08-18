package io.github.robc.jroot.crypto;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * PEM block splitting. A GSI proxy is one file holding a certificate, a
 * private key and the issuer chain, so pulling it apart by label is where
 * everything downstream starts.
 */
public final class Pem {

    private Pem() {}

    /** One {@code -----BEGIN <label>-----} block and the DER it wraps. */
    public record Block(String label, byte[] der) {}

    /**
     * Every PEM block in {@code data}, in file order. A block whose base64
     * will not decode is skipped rather than fatal: proxy files carry
     * material this reader has no opinion about, and losing a good chain
     * over one bad block would be the wrong trade.
     */
    public static List<Block> blocks(byte[] data) {
        List<Block> out = new ArrayList<>();
        String label = null;
        StringBuilder body = new StringBuilder();
        for (String raw : new String(data, StandardCharsets.ISO_8859_1).split("\n")) {
            String line = raw.strip();
            if (line.startsWith("-----BEGIN ") && line.endsWith("-----")) {
                label = line.substring(11, line.length() - 5).strip();
                body.setLength(0);
            } else if (line.startsWith("-----END ") && line.endsWith("-----")) {
                if (label != null && line.substring(9, line.length() - 5).strip().equals(label)) {
                    try {
                        out.add(new Block(label, Base64.getMimeDecoder()
                                .decode(body.toString())));
                    } catch (IllegalArgumentException ignored) {
                        // A corrupt block must not lose the good ones.
                    }
                }
                label = null;
                body.setLength(0);
            } else if (label != null) {
                body.append(line);
            }
        }
        return out;
    }

    /** The DER of every block carrying {@code label}. */
    public static List<byte[]> blocks(byte[] data, String label) {
        List<byte[]> out = new ArrayList<>();
        for (Block block : blocks(data)) {
            if (block.label().equals(label)) {
                out.add(block.der());
            }
        }
        return out;
    }

    /** Wrap {@code der} back into a PEM block, 64 characters to the line. */
    public static byte[] encode(String label, byte[] der) {
        String body = Base64.getEncoder().encodeToString(der);
        StringBuilder out = new StringBuilder("-----BEGIN ").append(label).append("-----\n");
        for (int i = 0; i < body.length(); i += 64) {
            out.append(body, i, Math.min(i + 64, body.length())).append('\n');
        }
        return out.append("-----END ").append(label).append("-----\n")
                .toString().getBytes(StandardCharsets.US_ASCII);
    }
}

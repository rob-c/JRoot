package io.github.robc.jroot.auth;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.github.robc.jroot.Config;

/**
 * Turning a server's security trailer into the mechanisms this client will
 * actually attempt, in order.
 *
 * <p>Every mechanism that cannot run records <em>why</em>. That list is the
 * whole value of the ladder: when nothing works, "no bearer token in
 * $BEARER_TOKEN or /tmp/bt_u1000, and /tmp/x509up_u1000 expired yesterday"
 * is a fixable problem, where "authentication failed" is a support ticket.
 */
public final class CredentialLadder {

    /** A mechanism the server offered and this client could build. */
    public record Candidate(SecurityOffer offer, Credential credential) {}

    private final List<Candidate> candidates;
    private final Map<String, String> rejections;

    private CredentialLadder(List<Candidate> candidates, Map<String, String> rejections) {
        this.candidates = List.copyOf(candidates);
        this.rejections = Map.copyOf(rejections);
    }

    public List<Candidate> candidates() {
        return candidates;
    }

    /** Mechanism name to the reason it was skipped, in offer order. */
    public Map<String, String> rejections() {
        return rejections;
    }

    public boolean isEmpty() {
        return candidates.isEmpty();
    }

    /** A sentence naming every mechanism that could not run and why. */
    public String explain() {
        if (rejections.isEmpty()) {
            return "the server offered no authentication mechanism this client speaks";
        }
        StringBuilder out = new StringBuilder();
        for (Map.Entry<String, String> entry : rejections.entrySet()) {
            if (!out.isEmpty()) {
                out.append("; ");
            }
            out.append(entry.getKey()).append(": ").append(entry.getValue());
        }
        return out.toString();
    }

    /**
     * Build the ladder for {@code offers}. A configured mechanism list
     * reorders and filters what the server offered; without one the server's
     * own order stands, which is how it expresses preference.
     */
    public static CredentialLadder build(List<SecurityOffer> offers, Config config) {
        List<SecurityOffer> ordered = order(offers, config.mechanisms());
        List<Candidate> candidates = new ArrayList<>();
        Map<String, String> rejections = new LinkedHashMap<>();
        for (SecurityOffer offer : ordered) {
            try {
                Optional<? extends Credential> credential = build(offer, config);
                if (credential.isPresent()) {
                    candidates.add(new Candidate(offer, credential.get()));
                } else {
                    rejections.putIfAbsent(offer.name(), notConfigured(offer.name()));
                }
            } catch (RuntimeException e) {
                // A mechanism that says why it cannot run is more useful than
                // one that vanishes: keep the reason, drop the mechanism.
                rejections.putIfAbsent(offer.name(), e.getMessage());
            }
        }
        return new CredentialLadder(candidates, rejections);
    }

    private static Optional<? extends Credential> build(SecurityOffer offer, Config config) {
        return switch (offer.name()) {
            case "ztn" -> TokenCredential.available(offer, config.token());
            case "gsi" -> GsiCredential.available(offer, config.proxyPath());
            case "unix" -> config.allowUnix()
                    ? Optional.of(new UnixCredential(config.username(), config.username()))
                    : Optional.empty();
            default -> Optional.empty();
        };
    }

    private static String notConfigured(String mechanism) {
        return switch (mechanism) {
            case "ztn" -> "no bearer token in $BEARER_TOKEN, $BEARER_TOKEN_FILE or "
                    + TokenCredential.searchPath();
            case "gsi" -> "no readable X.509 proxy at "
                    + io.github.robc.jroot.crypto.X509Proxy.defaultPath();
            case "unix" -> "unix authentication was turned off in this client";
            default -> "this client does not implement " + mechanism;
        };
    }

    private static List<SecurityOffer> order(List<SecurityOffer> offers, List<String> preferred) {
        if (preferred.isEmpty()) {
            return offers;
        }
        List<SecurityOffer> out = new ArrayList<>();
        for (String name : preferred) {
            for (SecurityOffer offer : offers) {
                if (offer.name().equals(name)) {
                    out.add(offer);
                }
            }
        }
        return out;
    }
}

package io.github.robc.jroot.auth;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** One {@code &P=name,params} clause of a {@code kXR_login} security trailer. */
public record SecurityOffer(String name, String params) {

    /** Parse {@code "&P=ztn,ver:1&P=unix"} into ordered offers. */
    public static List<SecurityOffer> parse(String sec) {
        List<SecurityOffer> offers = new ArrayList<>();
        if (sec == null) {
            return offers;
        }
        for (String clause : sec.split("&")) {
            if (!clause.startsWith("P=")) {
                continue;
            }
            String body = clause.substring(2).strip();
            if (body.isEmpty()) {
                continue;
            }
            int comma = body.indexOf(',');
            offers.add(comma < 0 ? new SecurityOffer(body, "")
                    : new SecurityOffer(body.substring(0, comma).strip(),
                            body.substring(comma + 1).strip()));
        }
        return offers;
    }

    /** {@code params} split on commas into {@code key:value} pairs. */
    public Map<String, String> options() {
        Map<String, String> out = new HashMap<>();
        for (String part : params.split(",")) {
            int colon = part.indexOf(':');
            if (colon > 0) {
                out.put(part.substring(0, colon).strip(), part.substring(colon + 1).strip());
            }
        }
        return out;
    }

    @Override
    public String toString() {
        return params.isEmpty() ? name : name + "," + params;
    }
}

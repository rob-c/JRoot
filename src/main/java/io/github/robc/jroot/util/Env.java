package io.github.robc.jroot.util;

import java.time.Duration;
import java.util.Locale;

/**
 * The {@code XRD_*} environment, read the way the reference client reads it.
 *
 * <p>A site tunes XRootD by exporting these on its worker nodes, and a job
 * inherits that tuning from whatever submitted it. A client that ignored
 * them would be quietly slower — or quietly less patient — than every other
 * client on the same node, for no reason an operator could see.
 *
 * <p>Nothing here fails. A variable that is unset, unparseable or out of
 * range leaves the caller's default alone, because the environment is advice
 * and a job should not die of a typo in somebody's profile.
 */
public final class Env {

    /** What a lookup returns when nothing is set: not a value. */
    public static final int UNSET = -1;

    private Env() {
    }

    public static String text(String variable) {
        String value = System.getenv(variable);
        return value == null ? "" : value.strip();
    }

    /** {@code variable} as a count within its sensible range, or {@link #UNSET}. */
    public static int number(String variable, int least, int most) {
        return parse(text(variable), least, most);
    }

    /** {@code variable} as a duration in seconds, or null when it says nothing. */
    public static Duration seconds(String variable) {
        int value = number(variable, 1, 86400);
        return value == UNSET ? null : Duration.ofSeconds(value);
    }

    /** Whether {@code variable} is set to something meaning yes. */
    public static boolean flag(String variable) {
        return flagOf(text(variable));
    }

    static int parse(String value, int least, int most) {
        if (value.isEmpty()) {
            return UNSET;
        }
        try {
            int parsed = Integer.parseInt(value);
            return parsed >= least && parsed <= most ? parsed : UNSET;
        } catch (NumberFormatException e) {
            return UNSET;
        }
    }

    static boolean flagOf(String value) {
        String set = value.toLowerCase(Locale.ROOT);
        return set.equals("1") || set.equals("true") || set.equals("yes");
    }
}

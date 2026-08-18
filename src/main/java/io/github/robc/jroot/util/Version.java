package io.github.robc.jroot.util;

/**
 * What this library calls itself when something asks.
 *
 * <p>The number comes from the jar's manifest, which Maven fills in from the
 * project version, so a build and the string it reports cannot drift apart.
 * Running from classes rather than a jar there is no manifest, and saying so
 * is better than inventing a number.
 */
public final class Version {

    /** The name the client goes by on a wire and in a monitoring stream. */
    public static final String NAME = "jroot";

    private static final String NUMBER =
            Version.class.getPackage().getImplementationVersion();

    private Version() {
    }

    /** The version, or {@code (development build)} outside a jar. */
    public static String number() {
        return NUMBER != null ? NUMBER : "(development build)";
    }

    /** Name and version as one token, for a field that identifies the client
     *  to a server: {@code jroot-0.1.0}. */
    public static String release() {
        return NUMBER != null ? NAME + "-" + NUMBER : NAME;
    }
}

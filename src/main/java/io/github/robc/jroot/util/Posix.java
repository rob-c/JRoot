package io.github.robc.jroot.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The one POSIX fact this client needs and the JDK does not expose: the
 * effective user id, which names the conventional credential paths
 * ({@code /tmp/x509up_u<uid>}, {@code /tmp/bt_u<uid>}).
 */
public final class Posix {

    private Posix() {}

    private static final int UID = probeUid();

    /** The user id, or -1 where it cannot be established. */
    public static int uid() {
        return UID;
    }

    private static int probeUid() {
        // /proc/self is owned by the process's real uid, which is exactly
        // what the credential-path conventions are built on.
        int uid = ownerOf(Path.of("/proc/self"));
        return uid >= 0 ? uid : ownerOf(Path.of(System.getProperty("user.home", "")));
    }

    private static int ownerOf(Path path) {
        try {
            Object uid = Files.getAttribute(path, "unix:uid");
            return uid instanceof Integer value ? value : -1;
        } catch (IOException | UnsupportedOperationException | IllegalArgumentException
                | SecurityException e) {
            return -1;
        }
    }
}

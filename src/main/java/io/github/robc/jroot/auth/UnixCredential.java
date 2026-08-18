package io.github.robc.jroot.auth;

import java.nio.charset.StandardCharsets;

/**
 * {@code unix} — the client simply asserts a user and group name. It proves
 * nothing, which is why servers only accept it where the network is the
 * trust boundary, but it is what a bare {@code xrootd} on a private cluster
 * expects and it costs nothing to offer.
 */
public final class UnixCredential implements Credential {

    private final String user;
    private final String group;

    public UnixCredential(String user, String group) {
        this.user = user;
        this.group = group;
    }

    public static UnixCredential ofCurrentUser() {
        String user = System.getProperty("user.name", "nobody");
        return new UnixCredential(user, user);
    }

    @Override
    public String name() {
        return "unix";
    }

    @Override
    public byte[] initial() {
        return ("unix\0" + user + " " + group).getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public String toString() {
        return "UnixCredential[" + user + ":" + group + "]";
    }
}

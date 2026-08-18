package io.github.robc.jroot.auth;

import io.github.robc.jroot.crypto.Signer;

/**
 * One authentication mechanism, ready to run. A credential is pure state:
 * it turns the server's security trailer into bytes and consumes challenges,
 * doing no I/O once the exchange has started — every file and environment
 * lookup happens when it is built.
 */
public interface Credential {

    /** Wire name, at most four bytes ({@code kXR_auth}'s credtype). */
    String name();

    /** The first {@code kXR_auth} credential blob. */
    byte[] initial();

    /**
     * Answer a {@code kXR_authmore} challenge, or return {@code null} when
     * the mechanism considers the exchange finished and the server should
     * not have asked again.
     */
    default byte[] step(byte[] challenge) {
        return null;
    }

    /**
     * The key {@code kXR_sigver} signs with, once the exchange establishes
     * one. {@code null} means this mechanism does not sign.
     */
    default byte[] sessionKey() {
        return null;
    }

    /**
     * The cipher that key is used under. Each mechanism brings its own: GSI
     * agrees an AES key over Diffie-Hellman, where {@code sss} has nothing to
     * agree and signs with the shared secret itself, under the same
     * {@code bf32} its credential was minted with.
     */
    default Signer.Cipher sessionCipher() {
        return Signer.Cipher.AES_CBC;
    }
}

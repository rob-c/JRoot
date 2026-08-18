package io.github.robc.jroot.client;

import io.github.robc.jroot.wire.Types.StatusInfo;

/**
 * What a request came back with, once the connection has folded away
 * everything that is not an answer: partial responses accumulated, waits
 * sat out, attention messages unwrapped.
 *
 * @param status the terminal status — {@code kXR_ok} or {@code kXR_status}
 * @param data   the response body, or for {@code kXR_status} the raw data
 *               that travelled after it
 * @param info   the {@code kXR_status} header, or {@code null}
 */
public record ServerResponse(int status, byte[] data, StatusInfo info) {

    public static ServerResponse ok(byte[] data) {
        return new ServerResponse(io.github.robc.jroot.wire.XrdConst.kXR_ok, data, null);
    }

    public boolean isEmpty() {
        return data.length == 0;
    }
}

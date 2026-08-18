package io.github.robc.jroot;

import io.github.robc.jroot.wire.XrdConst;

/** A {@code kXR_error} response: the server understood the request and refused it. */
public class XrdServerException extends XrdException {

    private final int code;

    public XrdServerException(int code, String message) {
        super(XrdConst.errorName(code) + ": " + message);
        this.code = code;
    }

    /** The {@code kXR_*} error code ({@link XrdConst}); HTTP failures are
     *  mapped onto the same table so one catch handles both transports. */
    public int code() {
        return code;
    }

    public boolean isNotFound() {
        return code == XrdConst.kXR_NotFound || code == XrdConst.kXR_noserver
                || code == XrdConst.kXR_noReplicas;
    }

    public boolean isPermissionDenied() {
        return code == XrdConst.kXR_NotAuthorized || code == XrdConst.kXR_AuthFailed
                || code == XrdConst.kXR_TLSRequired;
    }

    public boolean isAlreadyExists() {
        return code == XrdConst.kXR_ItExists;
    }
}

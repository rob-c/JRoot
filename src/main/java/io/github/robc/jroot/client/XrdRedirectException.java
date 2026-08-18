package io.github.robc.jroot.client;

import io.github.robc.jroot.XrdException;
import io.github.robc.jroot.wire.Types.RedirectInfo;

/**
 * A {@code kXR_redirect}, raised where a redirect cannot be followed in
 * place — during bring-up, or once a client has followed as many as it will.
 */
public class XrdRedirectException extends XrdException {

    private static final long serialVersionUID = 1L;

    private final transient RedirectInfo redirect;

    public XrdRedirectException(RedirectInfo redirect) {
        super("redirected to " + redirect.host() + ":" + redirect.actualPort()
                + (redirect.requiresTls() ? " over TLS" : ""));
        this.redirect = redirect;
    }

    public RedirectInfo redirect() {
        return redirect;
    }
}

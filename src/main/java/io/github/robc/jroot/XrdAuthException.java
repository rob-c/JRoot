package io.github.robc.jroot;

/** Authentication could not be completed: no usable mechanism, a failed
 *  exchange, or credential material that is absent or expired. */
public class XrdAuthException extends XrdException {

    public XrdAuthException(String message) {
        super(message);
    }

    public XrdAuthException(String message, Throwable cause) {
        super(message, cause);
    }
}

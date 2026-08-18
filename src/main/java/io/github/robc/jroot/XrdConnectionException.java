package io.github.robc.jroot;

/** The transport failed: connect refused, connection dropped, TLS failure. */
public class XrdConnectionException extends XrdException {

    public XrdConnectionException(String message) {
        super(message);
    }

    public XrdConnectionException(String message, Throwable cause) {
        super(message, cause);
    }
}

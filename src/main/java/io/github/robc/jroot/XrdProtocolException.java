package io.github.robc.jroot;

/** The peer sent bytes that do not parse as the protocol: truncated bodies,
 *  impossible lengths, statuses that make no sense in the current state. */
public class XrdProtocolException extends XrdException {

    public XrdProtocolException(String message) {
        super(message);
    }

    public XrdProtocolException(String message, Throwable cause) {
        super(message, cause);
    }
}

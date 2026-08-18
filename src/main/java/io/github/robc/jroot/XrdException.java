package io.github.robc.jroot;

/**
 * Base of every failure this library raises. Unchecked, because most calls
 * surface through {@code CompletableFuture} where checked exceptions cannot
 * travel anyway; catch this to catch everything JRoot can throw.
 */
public class XrdException extends RuntimeException {

    public XrdException(String message) {
        super(message);
    }

    public XrdException(String message, Throwable cause) {
        super(message, cause);
    }
}

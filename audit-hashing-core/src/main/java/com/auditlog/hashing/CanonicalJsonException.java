package com.auditlog.hashing;

/** Thrown when a payload cannot be canonicalized, and therefore cannot be hashed or stored. */
public class CanonicalJsonException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public CanonicalJsonException(String message) {
        super(message);
    }

    public CanonicalJsonException(String message, Throwable cause) {
        super(message, cause);
    }
}

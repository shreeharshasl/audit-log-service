package com.auditlog.service.exception;

/** A state change that is not allowed against the current record. */
public class EventConflictException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final String error;

    public EventConflictException(String error, String message) {
        super(message);
        this.error = error;
    }

    public String error() {
        return error;
    }

    public static EventConflictException archived(long seq) {
        return new EventConflictException("event_archived", "sequence " + seq + " is already archived");
    }

    public static EventConflictException alreadyRedacted(long seq, String path) {
        return new EventConflictException(
                "already_redacted", "path " + path + " on sequence " + seq + " is already redacted");
    }

    public static EventConflictException incompleteRange(long fromSeq, long toSeq, int found) {
        return new EventConflictException(
                "incomplete_range",
                "export range %d-%d is missing records (found %d); records cannot be deleted, only archived"
                        .formatted(fromSeq, toSeq, found));
    }
}

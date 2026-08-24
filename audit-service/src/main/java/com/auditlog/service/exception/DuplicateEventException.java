package com.auditlog.service.exception;

import java.util.UUID;

/**
 * Raised when an append reuses an existing event id.
 *
 * <p>Rejected rather than silently treated as a retry: an audit log that quietly discards a write
 * because it resembles an earlier one is indistinguishable from one that loses events.
 */
public class DuplicateEventException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public DuplicateEventException(UUID eventId) {
        super("event " + eventId + " has already been recorded");
    }
}

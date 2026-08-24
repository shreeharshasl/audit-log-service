package com.auditlog.hashing;

import java.time.Instant;
import java.util.UUID;

/**
 * The non-payload fields of a record, all of which are covered by the content hash.
 *
 * <p>Two timestamps, deliberately. {@code occurredAt} is supplied by the caller and describes when
 * the thing happened in their world; {@code recordedAt} is assigned by this service when the record
 * was accepted. Caller clocks are untrusted input, so {@code occurredAt} is evidence but never
 * authority: ordering comes from the sequence number alone. Both are hashed, so neither can be
 * quietly adjusted afterwards.
 */
public record AuditEventHeader(
        UUID eventId,
        String eventType,
        String actorId,
        String resourceType,
        String resourceId,
        Instant occurredAt,
        Instant recordedAt) {

    public AuditEventHeader {
        require(eventId != null, "eventId");
        require(eventType != null, "eventType");
        require(actorId != null, "actorId");
        require(resourceType != null, "resourceType");
        require(resourceId != null, "resourceId");
        require(occurredAt != null, "occurredAt");
        require(recordedAt != null, "recordedAt");
    }

    private static void require(boolean condition, String field) {
        if (!condition) {
            throw new IllegalArgumentException(field + " is required and is covered by the content hash");
        }
    }
}

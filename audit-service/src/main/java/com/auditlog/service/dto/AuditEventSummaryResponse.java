package com.auditlog.service.dto;

import java.time.Instant;
import java.util.UUID;

import com.auditlog.service.model.AuditRecord;

/** List-view of a record. Payload and commitments stay on the single-record fetch. */
public record AuditEventSummaryResponse(
        long seq,
        UUID eventId,
        String eventType,
        String actorId,
        String resourceType,
        String resourceId,
        Instant occurredAt,
        Instant recordedAt,
        String contentHash,
        String chainHash,
        int hashVersion,
        boolean archived) {

    public static AuditEventSummaryResponse from(AuditRecord record) {
        return new AuditEventSummaryResponse(
                record.seq(),
                record.header().eventId(),
                record.header().eventType(),
                record.header().actorId(),
                record.header().resourceType(),
                record.header().resourceId(),
                record.header().occurredAt(),
                record.header().recordedAt(),
                record.contentHashHex(),
                record.chainHashHex(),
                record.hashVersion(),
                record.archived());
    }
}

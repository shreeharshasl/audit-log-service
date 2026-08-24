package com.auditlog.service.dto;

import java.time.Instant;
import java.util.UUID;

import com.auditlog.service.model.AuditRecord;

public record AppendEventResponse(
        long seq,
        UUID eventId,
        Instant recordedAt,
        String payloadRoot,
        String contentHash,
        String chainHash,
        int hashVersion) {

    public static AppendEventResponse from(AuditRecord record) {
        return new AppendEventResponse(
                record.seq(),
                record.header().eventId(),
                record.header().recordedAt(),
                record.payloadRootHex(),
                record.contentHashHex(),
                record.chainHashHex(),
                record.hashVersion());
    }
}

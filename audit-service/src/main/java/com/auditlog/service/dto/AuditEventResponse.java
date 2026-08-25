package com.auditlog.service.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import com.auditlog.hashing.CanonicalJson;
import com.auditlog.hashing.FieldCommitment;
import com.auditlog.service.model.AuditRecord;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * @param payload returned as parsed JSON for convenience
 * @param canonicalPayload the exact bytes the hashes cover, so a caller can verify offline without
 *     having to reimplement canonicalization
 */
public record AuditEventResponse(
        long seq,
        UUID eventId,
        String eventType,
        String actorId,
        String resourceType,
        String resourceId,
        Instant occurredAt,
        Instant recordedAt,
        JsonNode payload,
        String canonicalPayload,
        String payloadRoot,
        String contentHash,
        String previousChainHash,
        String chainHash,
        int hashVersion,
        boolean archived,
        Instant archivedAt,
        List<FieldCommitmentResponse> commitments) {

    public AuditEventResponse {
        commitments = List.copyOf(commitments);
    }

    public static AuditEventResponse from(AuditRecord record, List<FieldCommitment> commitments) {
        return new AuditEventResponse(
                record.seq(),
                record.header().eventId(),
                record.header().eventType(),
                record.header().actorId(),
                record.header().resourceType(),
                record.header().resourceId(),
                record.header().occurredAt(),
                record.header().recordedAt(),
                CanonicalJson.parse(record.canonicalPayload()),
                record.canonicalPayload(),
                record.payloadRootHex(),
                record.contentHashHex(),
                record.previousChainHashHex(),
                record.chainHashHex(),
                record.hashVersion(),
                record.archived(),
                record.archivedAt(),
                commitments.stream().map(FieldCommitmentResponse::from).toList());
    }
}

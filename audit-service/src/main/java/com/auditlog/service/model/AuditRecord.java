package com.auditlog.service.model;

import java.time.Instant;

import com.auditlog.hashing.AuditEventHeader;

/**
 * A persisted audit record: the hashed header, the exact canonical payload bytes the commitments
 * were computed over, and the two hashes that make tampering detectable.
 *
 * @param canonicalPayload canonical JSON text, stored verbatim so hashes can be recomputed
 * @param previousChainHashHex the predecessor's chain hash, or the genesis value for seq 1
 * @param archived true once retention has redacted remaining fields in place
 */
public record AuditRecord(
        long seq,
        AuditEventHeader header,
        String canonicalPayload,
        String payloadRootHex,
        String contentHashHex,
        String previousChainHashHex,
        String chainHashHex,
        int hashVersion,
        boolean archived,
        Instant archivedAt) {}

package com.auditlog.hashing;

import java.util.List;

/** One audit record as it appears in an export bundle. */
public record ExportedRecord(
        long seq,
        AuditEventHeader header,
        String canonicalPayload,
        String payloadRootHex,
        String contentHashHex,
        String previousChainHashHex,
        String chainHashHex,
        int hashVersion,
        boolean archived,
        List<FieldCommitment> commitments) {

    public ExportedRecord {
        if (seq < 1) {
            throw new IllegalArgumentException("seq must be at least 1");
        }
        if (header == null) {
            throw new IllegalArgumentException("header is required");
        }
        if (canonicalPayload == null) {
            throw new IllegalArgumentException("canonicalPayload is required");
        }
        commitments = List.copyOf(commitments);
    }

    public ExportLink toLink() {
        return new ExportLink(seq, contentHashHex, chainHashHex);
    }
}

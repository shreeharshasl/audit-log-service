package com.auditlog.hashing;

import java.util.List;

/**
 * The commitment view of a payload: one commitment per position, plus the single hash over all of
 * them that the record's content hash actually covers.
 *
 * @param fields ordered by path, matching the order committed by the root
 */
public record CommittedPayload(List<FieldCommitment> fields, String payloadRootHex) {

    public CommittedPayload {
        fields = List.copyOf(fields);
    }
}

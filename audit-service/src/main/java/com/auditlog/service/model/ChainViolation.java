package com.auditlog.service.model;

/**
 * One detected inconsistency, named specifically enough to tell an operator what was altered rather
 * than only that something was.
 */
public record ChainViolation(long seq, Type type, String detail) {

    public enum Type {
        /** Stored content hash does not match a recomputation from the stored header fields. */
        CONTENT_HASH_MISMATCH,
        /** Stored chain hash does not match a recomputation from the stored predecessor and content. */
        CHAIN_HASH_MISMATCH,
        /** This record's recorded predecessor is not the chain hash of the record before it. */
        BROKEN_LINK,
        /** A sequence number is missing, so a record was deleted outright. */
        SEQUENCE_GAP,
        /** Stored commitments do not reproduce the payload root the content hash covers. */
        PAYLOAD_ROOT_MISMATCH,
        /** A field commitment does not match the stored canonical payload. */
        FIELD_COMMITMENT_INVALID
    }
}

package com.auditlog.service.dto;

import com.auditlog.hashing.FieldCommitment;

/**
 * @param salt present unless the field has been redacted; an external verifier needs it to
 *     recompute the commitment, and it reveals nothing on its own
 */
public record FieldCommitmentResponse(String path, String kind, String salt, String commitment, boolean redacted) {

    public static FieldCommitmentResponse from(FieldCommitment commitment) {
        return new FieldCommitmentResponse(
                commitment.path(),
                commitment.kind().name(),
                commitment.saltHex(),
                commitment.commitmentHex(),
                commitment.redacted());
    }
}

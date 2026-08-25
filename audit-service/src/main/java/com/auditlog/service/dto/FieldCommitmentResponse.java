package com.auditlog.service.dto;

import com.auditlog.hashing.FieldCommitment;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * @param salt present unless the field has been redacted; an external verifier needs it to
 *     recompute the commitment, and it reveals nothing on its own. Always serialized, including as
 *     {@code null} after redaction, so callers can tell the salt was dropped rather than omitted.
 */
public record FieldCommitmentResponse(
        String path,
        String kind,
        @JsonInclude(JsonInclude.Include.ALWAYS) String salt,
        String commitment,
        boolean redacted) {

    public static FieldCommitmentResponse from(FieldCommitment commitment) {
        return new FieldCommitmentResponse(
                commitment.path(),
                commitment.kind().name(),
                commitment.saltHex(),
                commitment.commitmentHex(),
                commitment.redacted());
    }
}

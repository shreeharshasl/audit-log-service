package com.auditlog.service.model;

import java.util.List;

/** Outcome of recomputing every hash across a range of records. */
public record ChainVerificationResult(long fromSeq, long toSeq, int recordsChecked, List<ChainViolation> violations) {

    public ChainVerificationResult {
        violations = List.copyOf(violations);
    }

    public boolean intact() {
        return violations.isEmpty();
    }
}

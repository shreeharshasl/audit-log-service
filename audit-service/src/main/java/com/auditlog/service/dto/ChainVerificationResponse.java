package com.auditlog.service.dto;

import java.util.List;

import com.auditlog.service.model.ChainVerificationResult;

public record ChainVerificationResponse(
        boolean intact, long fromSeq, long toSeq, int recordsChecked, List<ViolationResponse> violations) {

    public ChainVerificationResponse {
        violations = List.copyOf(violations);
    }

    public record ViolationResponse(long seq, String type, String detail) {}

    public static ChainVerificationResponse from(ChainVerificationResult result) {
        return new ChainVerificationResponse(
                result.intact(),
                result.fromSeq(),
                result.toSeq(),
                result.recordsChecked(),
                result.violations().stream()
                        .map(v -> new ViolationResponse(v.seq(), v.type().name(), v.detail()))
                        .toList());
    }
}

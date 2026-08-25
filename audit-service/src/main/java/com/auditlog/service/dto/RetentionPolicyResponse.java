package com.auditlog.service.dto;

import java.time.Instant;

import com.auditlog.service.model.RetentionPolicy;

public record RetentionPolicyResponse(int retainDays, Instant updatedAt) {

    public static RetentionPolicyResponse from(RetentionPolicy policy) {
        return new RetentionPolicyResponse(policy.retainDays(), policy.updatedAt());
    }
}

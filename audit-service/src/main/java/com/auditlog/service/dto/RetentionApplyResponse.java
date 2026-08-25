package com.auditlog.service.dto;

import java.time.Instant;

import com.auditlog.service.model.RetentionApplication;

public record RetentionApplyResponse(int archivedCount, int retainDays, Instant cutoff) {

    public static RetentionApplyResponse from(RetentionApplication application) {
        return new RetentionApplyResponse(application.archivedCount(), application.retainDays(), application.cutoff());
    }
}

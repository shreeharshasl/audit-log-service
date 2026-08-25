package com.auditlog.service.dto;

import java.util.List;

import com.auditlog.service.model.AuditEventPage;

public record AuditEventPageResponse(List<AuditEventSummaryResponse> items, boolean hasMore, Long nextBeforeSeq) {

    public AuditEventPageResponse {
        items = List.copyOf(items);
    }

    public static AuditEventPageResponse from(AuditEventPage page) {
        return new AuditEventPageResponse(
                page.items().stream().map(AuditEventSummaryResponse::from).toList(),
                page.hasMore(),
                page.nextBeforeSeq());
    }
}

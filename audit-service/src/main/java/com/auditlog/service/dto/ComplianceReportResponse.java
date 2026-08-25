package com.auditlog.service.dto;

import java.time.Instant;
import java.util.List;

import com.auditlog.service.dto.ChainVerificationResponse.ViolationResponse;
import com.auditlog.service.model.ComplianceReport;

public record ComplianceReportResponse(
        Instant generatedAt,
        ChainVerificationResponse chain,
        RetentionComplianceResponse retention,
        RedactionCountsResponse redaction,
        VolumeCountsResponse volume) {

    public record RetentionComplianceResponse(
            int retainDays, Instant cutoff, long eligibleUnarchived, long archivedCount, boolean compliant) {}

    public record RedactionCountsResponse(long redactedFieldCount, long eventsWithRedaction) {}

    public record VolumeCountsResponse(long totalEvents, List<EventTypeCountResponse> byEventType) {

        public VolumeCountsResponse {
            byEventType = List.copyOf(byEventType);
        }
    }

    public record EventTypeCountResponse(String eventType, long count) {}

    public static ComplianceReportResponse from(ComplianceReport report) {
        return new ComplianceReportResponse(
                report.generatedAt(),
                new ChainVerificationResponse(
                        report.chain().intact(),
                        report.chain().fromSeq(),
                        report.chain().toSeq(),
                        report.chain().recordsChecked(),
                        report.chain().violations().stream()
                                .map(v ->
                                        new ViolationResponse(v.seq(), v.type().name(), v.detail()))
                                .toList()),
                new RetentionComplianceResponse(
                        report.retention().retainDays(),
                        report.retention().cutoff(),
                        report.retention().eligibleUnarchived(),
                        report.retention().archivedCount(),
                        report.retention().compliant()),
                new RedactionCountsResponse(
                        report.redaction().redactedFieldCount(),
                        report.redaction().eventsWithRedaction()),
                new VolumeCountsResponse(
                        report.volume().totalEvents(),
                        report.volume().byEventType().stream()
                                .map(item -> new EventTypeCountResponse(item.eventType(), item.count()))
                                .toList()));
    }
}

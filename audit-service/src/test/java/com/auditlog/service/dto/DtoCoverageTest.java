package com.auditlog.service.dto;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.auditlog.service.model.ChainVerificationResult;
import com.auditlog.service.model.ChainViolation;
import com.auditlog.service.model.ComplianceReport;

class DtoCoverageTest {

    @Test
    @DisplayName("a null redaction path list is stored as empty rather than null")
    void nullRedactionPathsBecomeEmpty() {
        assertThat(new RedactEventRequest(null).paths()).isEmpty();
    }

    @Test
    @DisplayName("compliance report mapping includes each chain violation")
    void complianceReportMapsViolations() {
        var report = new ComplianceReport(
                Instant.parse("2026-01-01T00:00:00Z"),
                new ChainVerificationResult(
                        1, 1, 1, List.of(new ChainViolation(1, ChainViolation.Type.BROKEN_LINK, "gap"))),
                new ComplianceReport.RetentionCompliance(365, Instant.parse("2025-01-01T00:00:00Z"), 0, 0, true),
                new ComplianceReport.RedactionCounts(0, 0),
                new ComplianceReport.VolumeCounts(1, List.of(new ComplianceReport.EventTypeCount("login", 1))));

        ComplianceReportResponse response = ComplianceReportResponse.from(report);

        assertThat(response.chain().violations()).singleElement().satisfies(v -> {
            assertThat(v.seq()).isEqualTo(1);
            assertThat(v.type()).isEqualTo("BROKEN_LINK");
            assertThat(v.detail()).isEqualTo("gap");
        });
        assertThat(response.volume().byEventType()).singleElement().satisfies(item -> {
            assertThat(item.eventType()).isEqualTo("login");
            assertThat(item.count()).isEqualTo(1);
        });
    }
}

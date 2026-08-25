package com.auditlog.service.model;

import java.time.Instant;
import java.util.List;

/** Point-in-time view of chain integrity, retention, redaction, and volume. */
public record ComplianceReport(
        Instant generatedAt,
        ChainVerificationResult chain,
        RetentionCompliance retention,
        RedactionCounts redaction,
        VolumeCounts volume) {

    public record RetentionCompliance(
            int retainDays, Instant cutoff, long eligibleUnarchived, long archivedCount, boolean compliant) {}

    public record RedactionCounts(long redactedFieldCount, long eventsWithRedaction) {}

    public record VolumeCounts(long totalEvents, List<EventTypeCount> byEventType) {
        public VolumeCounts {
            byEventType = List.copyOf(byEventType);
        }
    }

    public record EventTypeCount(String eventType, long count) {}
}

package com.auditlog.service.service;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.auditlog.service.model.ChainVerificationResult;
import com.auditlog.service.model.ComplianceReport;
import com.auditlog.service.model.RetentionPolicy;
import com.auditlog.service.repository.AuditEventRepository;
import com.auditlog.service.repository.RetentionPolicyRepository;

/** Assembles chain integrity, retention, redaction, and volume into one report. */
@Service
public class ComplianceService {

    private final ChainVerificationService chainVerification;
    private final AuditEventRepository events;
    private final RetentionPolicyRepository policyRepository;
    private final Clock clock;

    public ComplianceService(
            ChainVerificationService chainVerification,
            AuditEventRepository events,
            RetentionPolicyRepository policyRepository,
            Clock clock) {
        this.chainVerification = chainVerification;
        this.events = events;
        this.policyRepository = policyRepository;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public ComplianceReport report() {
        Instant generatedAt = clock.instant().truncatedTo(ChronoUnit.MICROS);
        long latest = events.latestSeq();
        ChainVerificationResult chain =
                latest == 0 ? new ChainVerificationResult(1, 1, 0, List.of()) : chainVerification.verify(1, latest);

        RetentionPolicy policy = policyRepository.find();
        Instant cutoff = generatedAt.minus(policy.retainDays(), ChronoUnit.DAYS);
        long eligible = events.countEligibleUnarchived(cutoff);
        long archived = events.countArchived();

        return new ComplianceReport(
                generatedAt,
                chain,
                new ComplianceReport.RetentionCompliance(
                        policy.retainDays(), cutoff, eligible, archived, eligible == 0),
                new ComplianceReport.RedactionCounts(events.countRedactedFields(), events.countEventsWithRedaction()),
                new ComplianceReport.VolumeCounts(events.countEvents(), events.countByEventType()));
    }
}

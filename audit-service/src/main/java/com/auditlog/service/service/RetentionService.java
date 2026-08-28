package com.auditlog.service.service;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.auditlog.hashing.FieldCommitment;
import com.auditlog.service.exception.EventNotFoundException;
import com.auditlog.service.model.AuditRecord;
import com.auditlog.service.model.RetentionApplication;
import com.auditlog.service.model.RetentionPolicy;
import com.auditlog.service.repository.AuditEventRepository;
import com.auditlog.service.repository.RetentionPolicyRepository;

/**
 * Archives records in place when they fall outside the retention window. Archival is redaction of
 * every remaining field plus an {@code archived} flag — never a DELETE, which would be a chain gap.
 */
@Service
public class RetentionService {

    private final RetentionPolicyRepository policyRepository;
    private final AuditEventRepository events;
    private final Clock clock;
    private final PrivilegedActionAuditor auditor;

    public RetentionService(
            RetentionPolicyRepository policyRepository,
            AuditEventRepository events,
            Clock clock,
            PrivilegedActionAuditor auditor) {
        this.policyRepository = policyRepository;
        this.events = events;
        this.clock = clock;
        this.auditor = auditor;
    }

    @Transactional(readOnly = true)
    public RetentionPolicy policy() {
        return policyRepository.find();
    }

    @Transactional
    public RetentionPolicy updatePolicy(int retainDays, String actorId) {
        if (retainDays < 1 || retainDays > 36_500) {
            throw new IllegalArgumentException("retainDays must be between 1 and 36500");
        }
        RetentionPolicy policy =
                policyRepository.update(retainDays, clock.instant().truncatedTo(ChronoUnit.MICROS));
        auditor.policyUpdated(actorId, retainDays);
        return policy;
    }

    @Transactional
    public RetentionApplication apply(String actorId) {
        RetentionPolicy policy = policyRepository.find();
        Instant cutoff = clock.instant().minus(policy.retainDays(), ChronoUnit.DAYS);
        List<Long> seqs = events.findSeqsEligibleForArchive(cutoff);
        Instant archivedAt = clock.instant().truncatedTo(ChronoUnit.MICROS);
        int archived = 0;
        for (long seq : seqs) {
            archive(seq, archivedAt);
            archived++;
        }
        RetentionApplication result = new RetentionApplication(archived, policy.retainDays(), cutoff);
        auditor.retentionApplied(actorId, archived, policy.retainDays());
        return result;
    }

    private void archive(long seq, Instant archivedAt) {
        AuditRecord record = events.lockBySeq(seq).orElseThrow(() -> new EventNotFoundException(seq));
        if (record.archived()) {
            return;
        }
        for (FieldCommitment field : events.findCommitments(seq)) {
            if (!field.redacted()) {
                events.redactCommitment(seq, field.path());
            }
        }
        events.updateCanonicalPayload(seq, "{}");
        events.markArchived(seq, archivedAt);
    }
}

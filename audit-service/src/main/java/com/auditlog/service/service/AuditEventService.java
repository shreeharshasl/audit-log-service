package com.auditlog.service.service;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.auditlog.hashing.AuditEventHeader;
import com.auditlog.hashing.CanonicalJson;
import com.auditlog.hashing.CommittedPayload;
import com.auditlog.hashing.EventHasher;
import com.auditlog.hashing.FieldCommitment;
import com.auditlog.hashing.HashFormat;
import com.auditlog.hashing.Hex;
import com.auditlog.hashing.PayloadCommitter;
import com.auditlog.service.exception.DuplicateEventException;
import com.auditlog.service.exception.EventNotFoundException;
import com.auditlog.service.model.AuditRecord;
import com.auditlog.service.model.ChainHead;
import com.auditlog.service.model.NewAuditEvent;
import com.auditlog.service.repository.AuditEventRepository;

/** The append path and single-record reads. */
@Service
public class AuditEventService {

    private final AuditEventRepository repository;
    private final PayloadCommitter committer;
    private final Clock clock;

    public AuditEventService(AuditEventRepository repository, PayloadCommitter committer, Clock clock) {
        this.repository = repository;
        this.committer = committer;
        this.clock = clock;
    }

    /**
     * Appends one record to the end of the chain.
     *
     * <p>Ordering of the steps matters. Canonicalization and commitment are the only unbounded work
     * in this path and are where {@link com.auditlog.hashing.PayloadLimits} is enforced, so they
     * happen before the chain head is locked. Everything inside the lock is a constant number of
     * cheap operations, which keeps the serialized section short.
     */
    @Transactional
    public AuditRecord append(NewAuditEvent event) {
        UUID eventId = event.eventId() == null ? UUID.randomUUID() : event.eventId();

        String canonicalPayload = CanonicalJson.canonicalString(event.payload());
        CommittedPayload committed = committer.commit(event.payload());

        // Truncated to microseconds because that is the resolution timestamptz stores and the
        // resolution the content hash covers. Without this, a nanosecond-precision input would hash
        // to one value now and a different one after a round trip through the database.
        Instant occurredAt = event.occurredAt().truncatedTo(ChronoUnit.MICROS);
        Instant recordedAt = clock.instant().truncatedTo(ChronoUnit.MICROS);

        ChainHead head = repository.lockChainHead();

        // Safe as a check-then-act only because the lock above serializes every append.
        if (repository.existsByEventId(eventId)) {
            throw new DuplicateEventException(eventId);
        }

        AuditEventHeader header = new AuditEventHeader(
                eventId,
                event.eventType(),
                event.actorId(),
                event.resourceType(),
                event.resourceId(),
                occurredAt,
                recordedAt);

        byte[] contentHash = EventHasher.contentHash(header, Hex.decode(committed.payloadRootHex()));
        byte[] chainHash = EventHasher.chainHash(Hex.decode(head.lastChainHashHex()), contentHash);

        AuditRecord record = new AuditRecord(
                head.lastSeq() + 1,
                header,
                canonicalPayload,
                committed.payloadRootHex(),
                Hex.encode(contentHash),
                head.lastChainHashHex(),
                Hex.encode(chainHash),
                HashFormat.VERSION);

        try {
            repository.insert(record);
        } catch (DuplicateKeyException e) {
            throw new DuplicateEventException(eventId);
        }
        repository.insertCommitments(record.seq(), committed.fields());
        repository.advanceChainHead(record.seq(), record.chainHashHex());
        return record;
    }

    @Transactional(readOnly = true)
    public AuditRecord findBySeq(long seq) {
        return repository.findBySeq(seq).orElseThrow(() -> new EventNotFoundException(seq));
    }

    @Transactional(readOnly = true)
    public List<FieldCommitment> findCommitments(long seq) {
        return repository.findCommitments(seq);
    }

    @Transactional(readOnly = true)
    public long latestSeq() {
        return repository.latestSeq();
    }
}

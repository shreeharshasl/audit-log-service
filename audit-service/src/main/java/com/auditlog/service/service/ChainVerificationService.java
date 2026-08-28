package com.auditlog.service.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.auditlog.hashing.CanonicalJson;
import com.auditlog.hashing.CanonicalJsonException;
import com.auditlog.hashing.EventHasher;
import com.auditlog.hashing.FieldCommitment;
import com.auditlog.hashing.HashFormat;
import com.auditlog.hashing.Hex;
import com.auditlog.hashing.PayloadCommitter;
import com.auditlog.service.model.AuditRecord;
import com.auditlog.service.model.ChainVerificationResult;
import com.auditlog.service.model.ChainViolation;
import com.auditlog.service.repository.AuditEventRepository;

/**
 * Recomputes every stored hash from the stored data and reports what does not agree.
 *
 * <p>Nothing here trusts a stored hash. Each one is recomputed from the fields it is supposed to
 * cover, so a value edited in the database is caught by the recomputation rather than by comparing
 * two numbers an attacker could have updated together.
 */
@Service
public class ChainVerificationService {

    private final AuditEventRepository events;
    private final PayloadCommitter committer;

    public ChainVerificationService(AuditEventRepository events, PayloadCommitter committer) {
        this.events = events;
        this.committer = committer;
    }

    @Transactional(readOnly = true)
    public ChainVerificationResult verify(long fromSeq, long toSeq) {
        if (fromSeq < 1 || toSeq < fromSeq) {
            throw new IllegalArgumentException("fromSeq must be at least 1 and no greater than toSeq");
        }
        List<AuditRecord> records = events.findRange(fromSeq, toSeq);
        List<ChainViolation> violations = new ArrayList<>();

        String previousChainHash = null;
        long expectedSeq = fromSeq;
        long writtenHead = events.latestSeq();
        long expectedUntil = Math.min(toSeq, writtenHead);

        for (AuditRecord record : records) {
            reportMissingSeqs(expectedSeq, Math.min(record.seq() - 1, expectedUntil), violations);
            expectedSeq = record.seq() + 1;

            byte[] recomputedContent = verifyContentHash(record, violations);
            verifyChainHash(record, recomputedContent, violations);
            verifyLink(record, previousChainHash, violations);
            verifyPayload(record, violations);

            previousChainHash = record.chainHashHex();
        }
        reportMissingSeqs(expectedSeq, expectedUntil, violations);

        return new ChainVerificationResult(fromSeq, toSeq, records.size(), violations);
    }

    private static void reportMissingSeqs(long from, long until, List<ChainViolation> violations) {
        for (long seq = from; seq <= until; seq++) {
            violations.add(new ChainViolation(
                    seq,
                    ChainViolation.Type.UNAUTHORIZED_ARCHIVE,
                    "sequence %d is missing; records cannot be deleted, only archived in place".formatted(seq)));
        }
    }

    private byte[] verifyContentHash(AuditRecord record, List<ChainViolation> violations) {
        byte[] recomputed = EventHasher.contentHash(record.header(), Hex.decode(record.payloadRootHex()));
        if (!Hex.encode(recomputed).equals(record.contentHashHex())) {
            violations.add(new ChainViolation(
                    record.seq(),
                    ChainViolation.Type.CONTENT_HASH_MISMATCH,
                    "stored content hash %s but the record's fields hash to %s"
                            .formatted(record.contentHashHex(), Hex.encode(recomputed))));
        }
        return recomputed;
    }

    private void verifyChainHash(AuditRecord record, byte[] contentHash, List<ChainViolation> violations) {
        byte[] recomputed = EventHasher.chainHash(Hex.decode(record.previousChainHashHex()), contentHash);
        if (!Hex.encode(recomputed).equals(record.chainHashHex())) {
            violations.add(new ChainViolation(
                    record.seq(),
                    ChainViolation.Type.CHAIN_HASH_MISMATCH,
                    "stored chain hash %s but the link recomputes to %s"
                            .formatted(record.chainHashHex(), Hex.encode(recomputed))));
        }
    }

    /**
     * Checks that this record points at its actual predecessor. The first record in the range can
     * only be checked when the range starts at the beginning of the chain, where the predecessor is
     * the fixed genesis value.
     */
    private void verifyLink(AuditRecord record, String previousChainHash, List<ChainViolation> violations) {
        String expected = previousChainHash;
        if (expected == null) {
            if (record.seq() != 1) {
                return;
            }
            expected = HashFormat.GENESIS_CHAIN_HASH;
        }
        if (!record.previousChainHashHex().equals(expected)) {
            violations.add(new ChainViolation(
                    record.seq(),
                    ChainViolation.Type.BROKEN_LINK,
                    "record claims predecessor %s but the preceding chain hash is %s"
                            .formatted(record.previousChainHashHex(), expected)));
        }
    }

    private void verifyPayload(AuditRecord record, List<ChainViolation> violations) {
        List<FieldCommitment> stored = events.findCommitments(record.seq());

        String recomputedRoot = Hex.encode(PayloadCommitter.payloadRoot(stored));
        if (!recomputedRoot.equals(record.payloadRootHex())) {
            violations.add(new ChainViolation(
                    record.seq(),
                    ChainViolation.Type.PAYLOAD_ROOT_MISMATCH,
                    "stored commitments hash to %s but the record's payload root is %s"
                            .formatted(recomputedRoot, record.payloadRootHex())));
            return;
        }

        try {
            committer.verify(CanonicalJson.parse(record.canonicalPayload()), stored).stream()
                    .filter(PayloadCommitter.CommitmentCheck::isViolation)
                    .forEach(check -> violations.add(new ChainViolation(
                            record.seq(),
                            ChainViolation.Type.FIELD_COMMITMENT_INVALID,
                            "%s at %s".formatted(check.status(), check.path()))));
        } catch (CanonicalJsonException e) {
            violations.add(new ChainViolation(
                    record.seq(),
                    ChainViolation.Type.FIELD_COMMITMENT_INVALID,
                    "stored payload is no longer canonical JSON: " + e.getMessage()));
        }
    }
}

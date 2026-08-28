package com.auditlog.service.service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.auditlog.hashing.CanonicalJson;
import com.auditlog.hashing.FieldCommitment;
import com.auditlog.hashing.PayloadRedactor;
import com.auditlog.service.exception.EventConflictException;
import com.auditlog.service.exception.EventNotFoundException;
import com.auditlog.service.exception.FieldPathNotFoundException;
import com.auditlog.service.model.AuditRecord;
import com.auditlog.service.repository.AuditEventRepository;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * Drops values and salts at selected JSON Pointers. Commitments stay, so hashes and the chain do
 * not change.
 */
@Service
public class RedactionService {

    private final AuditEventRepository events;
    private final PrivilegedActionAuditor auditor;

    public RedactionService(AuditEventRepository events, PrivilegedActionAuditor auditor) {
        this.events = events;
        this.auditor = auditor;
    }

    @Transactional
    public AuditRecord redact(long seq, List<String> paths, String actorId) {
        if (paths == null || paths.isEmpty()) {
            throw new IllegalArgumentException("at least one path is required");
        }
        AuditRecord record = events.lockBySeq(seq).orElseThrow(() -> new EventNotFoundException(seq));
        if (record.archived()) {
            throw EventConflictException.archived(seq);
        }

        List<FieldCommitment> commitments = events.findCommitments(seq);
        Set<String> requested = new LinkedHashSet<>(paths);
        List<String> leavesToRedact = new ArrayList<>();
        for (String path : requested) {
            List<FieldCommitment> matches = commitments.stream()
                    .filter(field -> matchesPath(field.path(), path))
                    .toList();
            if (matches.isEmpty()) {
                throw new FieldPathNotFoundException(seq, path);
            }
            if (matches.stream().allMatch(FieldCommitment::redacted)) {
                throw EventConflictException.alreadyRedacted(seq, path);
            }
            matches.stream()
                    .filter(field -> !field.redacted())
                    .map(FieldCommitment::path)
                    .forEach(leavesToRedact::add);
        }

        List<String> jsonPaths = collapseToAncestors(requested);
        JsonNode redactedPayload =
                PayloadRedactor.removePaths(CanonicalJson.parse(record.canonicalPayload()), jsonPaths);
        events.updateCanonicalPayload(seq, CanonicalJson.canonicalString(redactedPayload));
        for (String leaf : leavesToRedact) {
            events.redactCommitment(seq, leaf);
        }
        AuditRecord stored = events.findBySeq(seq).orElseThrow(() -> new EventNotFoundException(seq));
        auditor.redacted(actorId, seq, jsonPaths);
        return stored;
    }

    static boolean matchesPath(String fieldPath, String requested) {
        return fieldPath.equals(requested) || fieldPath.startsWith(requested + "/");
    }

    /**
     * If both {@code /account} and {@code /account/number} are requested, only {@code /account}
     * needs to be removed from the JSON tree.
     */
    static List<String> collapseToAncestors(Set<String> paths) {
        List<String> sorted =
                paths.stream().sorted(Comparator.comparingInt(String::length)).toList();
        List<String> kept = new ArrayList<>();
        for (String path : sorted) {
            boolean covered = kept.stream().anyMatch(parent -> path.equals(parent) || path.startsWith(parent + "/"));
            if (!covered) {
                kept.add(path);
            }
        }
        return kept;
    }
}

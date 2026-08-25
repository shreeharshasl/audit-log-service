package com.auditlog.service.service;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.auditlog.hashing.ExportBundle;
import com.auditlog.hashing.ExportHasher;
import com.auditlog.hashing.ExportedRecord;
import com.auditlog.hashing.HashFormat;
import com.auditlog.hashing.Hex;
import com.auditlog.service.exception.EventConflictException;
import com.auditlog.service.exception.ExportNotFoundException;
import com.auditlog.service.model.AuditRecord;
import com.auditlog.service.model.ExportMetadata;
import com.auditlog.service.model.GeneratedExport;
import com.auditlog.service.repository.AuditEventRepository;
import com.auditlog.service.repository.ExportRepository;

/**
 * Builds a JSON bundle a recipient can verify with the hashing core alone, and stores enough
 * metadata to regenerate it later from the live (possibly redacted) store.
 */
@Service
public class ExportService {

    private final AuditEventRepository events;
    private final ExportRepository exports;
    private final Clock clock;

    public ExportService(AuditEventRepository events, ExportRepository exports, Clock clock) {
        this.events = events;
        this.exports = exports;
        this.clock = clock;
    }

    @Transactional
    public GeneratedExport create(long fromSeq, long toSeq) {
        ExportBundle bundle = bundleFor(fromSeq, toSeq);
        Instant createdAt = clock.instant().truncatedTo(ChronoUnit.MICROS);
        UUID exportId = UUID.randomUUID();
        exports.insert(new ExportMetadata(
                exportId, fromSeq, toSeq, bundle.records().size(), bundle.manifestHashHex(), createdAt));
        return new GeneratedExport(exportId, createdAt, bundle);
    }

    @Transactional(readOnly = true)
    public GeneratedExport regenerate(UUID exportId) {
        ExportMetadata metadata = exports.findById(exportId).orElseThrow(() -> new ExportNotFoundException(exportId));
        ExportBundle bundle = bundleFor(metadata.fromSeq(), metadata.toSeq());
        return new GeneratedExport(metadata.exportId(), metadata.createdAt(), bundle);
    }

    private ExportBundle bundleFor(long fromSeq, long toSeq) {
        if (fromSeq < 1 || toSeq < fromSeq) {
            throw new IllegalArgumentException("fromSeq must be at least 1 and no greater than toSeq");
        }
        List<AuditRecord> records = events.findRange(fromSeq, toSeq);
        long expectedCount = toSeq - fromSeq + 1;
        if (records.size() != expectedCount) {
            throw EventConflictException.incompleteRange(fromSeq, toSeq, records.size());
        }
        List<ExportedRecord> exported = new ArrayList<>(records.size());
        for (AuditRecord record : records) {
            exported.add(toExported(record));
        }
        String manifest = Hex.encode(ExportHasher.manifestHash(
                HashFormat.VERSION,
                fromSeq,
                toSeq,
                exported.stream().map(ExportedRecord::toLink).toList()));
        return new ExportBundle(HashFormat.VERSION, fromSeq, toSeq, manifest, exported);
    }

    private ExportedRecord toExported(AuditRecord record) {
        return new ExportedRecord(
                record.seq(),
                record.header(),
                record.canonicalPayload(),
                record.payloadRootHex(),
                record.contentHashHex(),
                record.previousChainHashHex(),
                record.chainHashHex(),
                record.hashVersion(),
                record.archived(),
                events.findCommitments(record.seq()));
    }
}

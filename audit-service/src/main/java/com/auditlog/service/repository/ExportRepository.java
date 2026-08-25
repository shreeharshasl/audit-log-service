package com.auditlog.service.repository;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import com.auditlog.service.model.ExportMetadata;

@Repository
public class ExportRepository {

    private static final RowMapper<ExportMetadata> MAPPER = (rs, rowNum) -> new ExportMetadata(
            rs.getObject("export_id", UUID.class),
            rs.getLong("from_seq"),
            rs.getLong("to_seq"),
            rs.getInt("record_count"),
            rs.getString("manifest_hash"),
            rs.getObject("created_at", OffsetDateTime.class).toInstant());

    private final JdbcTemplate jdbc;

    public ExportRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void insert(ExportMetadata metadata) {
        jdbc.update(
                """
                INSERT INTO audit_export (export_id, from_seq, to_seq, record_count, manifest_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                metadata.exportId(),
                metadata.fromSeq(),
                metadata.toSeq(),
                metadata.recordCount(),
                metadata.manifestHashHex(),
                OffsetDateTime.ofInstant(metadata.createdAt(), ZoneOffset.UTC));
    }

    public Optional<ExportMetadata> findById(UUID exportId) {
        return jdbc
                .query(
                        "SELECT export_id, from_seq, to_seq, record_count, manifest_hash, created_at FROM audit_export WHERE export_id = ?",
                        MAPPER,
                        exportId)
                .stream()
                .findFirst();
    }
}

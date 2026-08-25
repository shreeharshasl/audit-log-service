package com.auditlog.service.repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import com.auditlog.hashing.AuditEventHeader;
import com.auditlog.hashing.FieldCommitment;
import com.auditlog.hashing.PayloadLeaf.LeafKind;
import com.auditlog.service.model.AuditEventQuery;
import com.auditlog.service.model.AuditRecord;
import com.auditlog.service.model.ChainHead;

/** SQL and row mapping for the audit log. Contains no business rules. */
@Repository
public class AuditEventRepository {

    private static final String LOCK_CHAIN_HEAD =
            "SELECT last_seq, last_chain_hash FROM audit_chain_head WHERE id = 1 FOR UPDATE";

    private static final String ADVANCE_CHAIN_HEAD =
            "UPDATE audit_chain_head SET last_seq = ?, last_chain_hash = ? WHERE id = 1";

    private static final String INSERT_EVENT =
            """
            INSERT INTO audit_event (
                seq, event_id, event_type, actor_id, resource_type, resource_id,
                occurred_at, recorded_at, canonical_payload, payload_root,
                content_hash, prev_chain_hash, chain_hash, hash_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;

    private static final String INSERT_COMMITMENT =
            """
            INSERT INTO audit_field_commitment (
                event_seq, field_path, leaf_kind, salt_hex, commitment_hex, redacted)
            VALUES (?, ?, ?, ?, ?, ?)
            """;

    private static final String SELECT_COLUMNS =
            """
            SELECT seq, event_id, event_type, actor_id, resource_type, resource_id,
                   occurred_at, recorded_at, canonical_payload, payload_root,
                   content_hash, prev_chain_hash, chain_hash, hash_version
            FROM audit_event
            """;

    private static final String SELECT_BY_SEQ = SELECT_COLUMNS + " WHERE seq = ?";

    private static final String SELECT_RANGE = SELECT_COLUMNS + " WHERE seq BETWEEN ? AND ? ORDER BY seq";

    private static final String SELECT_COMMITMENTS =
            """
            SELECT field_path, leaf_kind, salt_hex, commitment_hex, redacted
            FROM audit_field_commitment
            WHERE event_seq = ?
            ORDER BY field_path
            """;

    private final JdbcTemplate jdbc;

    public AuditEventRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * Reads the chain tip and holds a row lock on it until the transaction commits.
     *
     * <p>This lock is what keeps the chain linear. Without it two concurrent appends both read the
     * same predecessor hash and both claim to follow it, leaving a fork that verification reports as
     * corruption even though nobody tampered with anything.
     */
    public ChainHead lockChainHead() {
        return jdbc.queryForObject(
                LOCK_CHAIN_HEAD,
                (rs, rowNum) -> new ChainHead(rs.getLong("last_seq"), rs.getString("last_chain_hash")));
    }

    public void advanceChainHead(long seq, String chainHashHex) {
        jdbc.update(ADVANCE_CHAIN_HEAD, seq, chainHashHex);
    }

    public void insert(AuditRecord record) {
        AuditEventHeader header = record.header();
        jdbc.update(
                INSERT_EVENT,
                record.seq(),
                header.eventId(),
                header.eventType(),
                header.actorId(),
                header.resourceType(),
                header.resourceId(),
                OffsetDateTime.ofInstant(header.occurredAt(), java.time.ZoneOffset.UTC),
                OffsetDateTime.ofInstant(header.recordedAt(), java.time.ZoneOffset.UTC),
                record.canonicalPayload(),
                record.payloadRootHex(),
                record.contentHashHex(),
                record.previousChainHashHex(),
                record.chainHashHex(),
                record.hashVersion());
    }

    public void insertCommitments(long seq, List<FieldCommitment> commitments) {
        List<Object[]> batch = new ArrayList<>(commitments.size());
        for (FieldCommitment c : commitments) {
            batch.add(new Object[] {seq, c.path(), c.kind().name(), c.saltHex(), c.commitmentHex(), c.redacted()});
        }
        jdbc.batchUpdate(INSERT_COMMITMENT, batch);
    }

    public boolean existsByEventId(UUID eventId) {
        Long count = jdbc.queryForObject("SELECT count(*) FROM audit_event WHERE event_id = ?", Long.class, eventId);
        return count != null && count > 0;
    }

    public Optional<AuditRecord> findBySeq(long seq) {
        return jdbc.query(SELECT_BY_SEQ, RECORD_MAPPER, seq).stream().findFirst();
    }

    public List<AuditRecord> findRange(long fromSeq, long toSeq) {
        return jdbc.query(SELECT_RANGE, RECORD_MAPPER, fromSeq, toSeq);
    }

    /**
     * Newest-first keyset page. {@code fetchLimit} is the number of rows to return, typically one
     * more than the caller's page size so the service can tell whether another page exists.
     */
    public List<AuditRecord> findPage(AuditEventQuery query, int fetchLimit) {
        StringBuilder sql = new StringBuilder(SELECT_COLUMNS);
        sql.append(" WHERE 1=1");
        List<Object> args = new ArrayList<>();
        if (query.beforeSeq() != null) {
            sql.append(" AND seq < ?");
            args.add(query.beforeSeq());
        }
        if (query.actorId() != null) {
            sql.append(" AND actor_id = ?");
            args.add(query.actorId());
        }
        if (query.eventType() != null) {
            sql.append(" AND event_type = ?");
            args.add(query.eventType());
        }
        if (query.resourceType() != null) {
            sql.append(" AND resource_type = ?");
            args.add(query.resourceType());
        }
        if (query.resourceId() != null) {
            sql.append(" AND resource_id = ?");
            args.add(query.resourceId());
        }
        sql.append(" ORDER BY seq DESC LIMIT ?");
        args.add(fetchLimit);
        return jdbc.query(sql.toString(), RECORD_MAPPER, args.toArray());
    }

    public List<FieldCommitment> findCommitments(long seq) {
        return jdbc.query(SELECT_COMMITMENTS, COMMITMENT_MAPPER, seq);
    }

    public long latestSeq() {
        Long seq = jdbc.queryForObject("SELECT last_seq FROM audit_chain_head WHERE id = 1", Long.class);
        return seq == null ? 0L : seq;
    }

    private static final RowMapper<AuditRecord> RECORD_MAPPER = (rs, rowNum) -> new AuditRecord(
            rs.getLong("seq"),
            new AuditEventHeader(
                    rs.getObject("event_id", UUID.class),
                    rs.getString("event_type"),
                    rs.getString("actor_id"),
                    rs.getString("resource_type"),
                    rs.getString("resource_id"),
                    instantAt(rs, "occurred_at"),
                    instantAt(rs, "recorded_at")),
            rs.getString("canonical_payload"),
            rs.getString("payload_root"),
            rs.getString("content_hash"),
            rs.getString("prev_chain_hash"),
            rs.getString("chain_hash"),
            rs.getInt("hash_version"));

    private static final RowMapper<FieldCommitment> COMMITMENT_MAPPER = (rs, rowNum) -> new FieldCommitment(
            rs.getString("field_path"),
            LeafKind.valueOf(rs.getString("leaf_kind")),
            rs.getString("salt_hex"),
            rs.getString("commitment_hex"),
            rs.getBoolean("redacted"));

    /**
     * Reads a {@code timestamptz} without going through {@code java.sql.Timestamp}, which would
     * reinterpret the value in the JVM default zone and shift the instant that gets hashed.
     */
    private static java.time.Instant instantAt(ResultSet rs, String column) throws SQLException {
        return rs.getObject(column, OffsetDateTime.class).toInstant();
    }
}

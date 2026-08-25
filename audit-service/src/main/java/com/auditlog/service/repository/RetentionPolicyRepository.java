package com.auditlog.service.repository;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import com.auditlog.service.model.RetentionPolicy;

@Repository
public class RetentionPolicyRepository {

    private static final RowMapper<RetentionPolicy> MAPPER = (rs, rowNum) -> new RetentionPolicy(
            rs.getInt("retain_days"),
            rs.getObject("updated_at", OffsetDateTime.class).toInstant());

    private final JdbcTemplate jdbc;

    public RetentionPolicyRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public RetentionPolicy find() {
        return jdbc.queryForObject("SELECT retain_days, updated_at FROM audit_retention_policy WHERE id = 1", MAPPER);
    }

    public RetentionPolicy update(int retainDays, Instant updatedAt) {
        jdbc.update(
                "UPDATE audit_retention_policy SET retain_days = ?, updated_at = ? WHERE id = 1",
                retainDays,
                OffsetDateTime.ofInstant(updatedAt, ZoneOffset.UTC));
        return new RetentionPolicy(retainDays, updatedAt);
    }
}

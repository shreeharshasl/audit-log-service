package com.auditlog.service.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

@ExtendWith(MockitoExtension.class)
class AuditEventRepositoryTest {

    @Mock
    private JdbcTemplate jdbc;

    @Test
    @DisplayName("a null count is treated as absent rather than a crash")
    void nullCountsAreZero() {
        AuditEventRepository repository = new AuditEventRepository(jdbc);
        when(jdbc.queryForObject(anyString(), eq(Long.class))).thenReturn(null);
        when(jdbc.queryForObject(anyString(), eq(Long.class), any())).thenReturn(null);
        when(jdbc.queryForObject(anyString(), eq(Long.class), any(UUID.class))).thenReturn(null);

        assertThat(repository.countArchived()).isZero();
        assertThat(repository.countEvents()).isZero();
        assertThat(repository.countRedactedFields()).isZero();
        assertThat(repository.countEventsWithRedaction()).isZero();
        assertThat(repository.latestSeq()).isZero();
        assertThat(repository.countEligibleUnarchived(Instant.parse("2026-01-01T00:00:00Z")))
                .isZero();
        assertThat(repository.existsByEventId(UUID.fromString("11111111-1111-1111-1111-111111111111")))
                .isFalse();
    }

    @Test
    @DisplayName("a positive count means the event id is already stored")
    void positiveCountMeansEventIdExists() {
        AuditEventRepository repository = new AuditEventRepository(jdbc);
        when(jdbc.queryForObject(anyString(), eq(Long.class), any(UUID.class))).thenReturn(1L);

        assertThat(repository.existsByEventId(UUID.fromString("11111111-1111-1111-1111-111111111111")))
                .isTrue();
    }
}

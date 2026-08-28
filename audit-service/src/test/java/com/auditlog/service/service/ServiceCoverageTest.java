package com.auditlog.service.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DuplicateKeyException;

import com.auditlog.hashing.AuditEventHeader;
import com.auditlog.hashing.CanonicalJson;
import com.auditlog.hashing.CommittedPayload;
import com.auditlog.hashing.EventHasher;
import com.auditlog.hashing.FieldCommitment;
import com.auditlog.hashing.HashFormat;
import com.auditlog.hashing.Hex;
import com.auditlog.hashing.PayloadCommitter;
import com.auditlog.service.config.AuditProperties;
import com.auditlog.service.exception.DuplicateEventException;
import com.auditlog.service.exception.EventNotFoundException;
import com.auditlog.service.exception.ExportNotFoundException;
import com.auditlog.service.model.AuditEventQuery;
import com.auditlog.service.model.AuditRecord;
import com.auditlog.service.model.ChainHead;
import com.auditlog.service.model.ChainViolation;
import com.auditlog.service.model.NewAuditEvent;
import com.auditlog.service.model.RetentionPolicy;
import com.auditlog.service.repository.AuditEventRepository;
import com.auditlog.service.repository.ExportRepository;
import com.auditlog.service.repository.RetentionPolicyRepository;

@ExtendWith(MockitoExtension.class)
class ServiceCoverageTest {

    private static final Instant NOW = Instant.parse("2026-06-01T12:00:00Z");

    @Mock
    private AuditEventRepository events;

    @Mock
    private ExportRepository exports;

    @Mock
    private RetentionPolicyRepository policies;

    @Test
    @DisplayName("an invalid verify range is rejected before the chain is walked")
    void verifyRejectsInvalidRange() {
        ChainVerificationService service = new ChainVerificationService(events, new PayloadCommitter());

        assertThatThrownBy(() -> service.verify(0, 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.verify(3, 1)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("a slice that does not include seq 1 cannot check the genesis link")
    void verifySliceNotStartingAtGenesisSkipsPredecessor() {
        Stored second = stored(2, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":2}");
        when(events.findRange(2, 2)).thenReturn(List.of(second.record()));
        when(events.latestSeq()).thenReturn(2L);
        when(events.findCommitments(2)).thenReturn(second.fields());

        var result = new ChainVerificationService(events, new PayloadCommitter()).verify(2, 2);

        assertThat(result.violations())
                .extracting(ChainViolation::type)
                .doesNotContain(ChainViolation.Type.BROKEN_LINK);
    }

    @Test
    @DisplayName("a payload root that no longer matches stored commitments is reported")
    void verifyDetectsPayloadRootMismatch() {
        Stored honest = stored(1, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":1}");
        AuditRecord tampered = new AuditRecord(
                honest.record().seq(),
                honest.record().header(),
                honest.record().canonicalPayload(),
                "ab".repeat(32),
                honest.record().contentHashHex(),
                honest.record().previousChainHashHex(),
                honest.record().chainHashHex(),
                honest.record().hashVersion(),
                false,
                null);
        when(events.findRange(1, 1)).thenReturn(List.of(tampered));
        when(events.latestSeq()).thenReturn(1L);
        when(events.findCommitments(1)).thenReturn(honest.fields());

        var result = new ChainVerificationService(events, new PayloadCommitter()).verify(1, 1);

        assertThat(result.violations())
                .extracting(ChainViolation::type)
                .contains(ChainViolation.Type.PAYLOAD_ROOT_MISMATCH);
    }

    @Test
    @DisplayName("a payload that is no longer JSON is a field-commitment failure")
    void verifyDetectsNonCanonicalPayload() {
        Stored honest = stored(1, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":1}");
        AuditRecord tampered = new AuditRecord(
                honest.record().seq(),
                honest.record().header(),
                "{",
                honest.record().payloadRootHex(),
                honest.record().contentHashHex(),
                honest.record().previousChainHashHex(),
                honest.record().chainHashHex(),
                honest.record().hashVersion(),
                false,
                null);
        when(events.findRange(1, 1)).thenReturn(List.of(tampered));
        when(events.latestSeq()).thenReturn(1L);
        when(events.findCommitments(1)).thenReturn(honest.fields());

        var result = new ChainVerificationService(events, new PayloadCommitter()).verify(1, 1);

        assertThat(result.violations())
                .extracting(ChainViolation::type)
                .contains(ChainViolation.Type.FIELD_COMMITMENT_INVALID);
    }

    @Test
    @DisplayName("redaction with no paths is rejected")
    void redactRejectsEmptyPaths() {
        RedactionService service = new RedactionService(events);

        assertThatThrownBy(() -> service.redact(1, List.of())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.redact(1, null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("redacting a missing sequence is not found")
    void redactMissingSeqIsNotFound() {
        when(events.lockBySeq(9)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> new RedactionService(events).redact(9, List.of("/amount")))
                .isInstanceOf(EventNotFoundException.class);
    }

    @Test
    @DisplayName("a parent path covers nested leaves")
    void parentPathMatchesNestedLeaves() {
        assertThat(RedactionService.matchesPath("/account/number", "/account")).isTrue();
        assertThat(RedactionService.matchesPath("/amount", "/account")).isFalse();
        assertThat(RedactionService.collapseToAncestors(Set.of("/account", "/account/number")))
                .containsExactly("/account");
    }

    @Test
    @DisplayName("retainDays outside the allowed window is rejected")
    void retentionRejectsInvalidWindow() {
        RetentionService service = new RetentionService(policies, events, Clock.fixed(NOW, ZoneOffset.UTC));

        assertThatThrownBy(() -> service.updatePolicy(0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.updatePolicy(36_501)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("archiving a sequence that disappeared is not found")
    void archiveMissingSeqIsNotFound() {
        when(policies.find()).thenReturn(new RetentionPolicy(1, NOW));
        when(events.findSeqsEligibleForArchive(any())).thenReturn(List.of(1L));
        when(events.lockBySeq(1)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> new RetentionService(policies, events, Clock.fixed(NOW, ZoneOffset.UTC)).apply())
                .isInstanceOf(EventNotFoundException.class);
    }

    @Test
    @DisplayName("an already-archived row is skipped on a later apply")
    void archiveSkipsAlreadyArchivedRows() {
        AuditRecord archived = new AuditRecord(
                1,
                header(),
                "{}",
                "aa".repeat(32),
                "bb".repeat(32),
                HashFormat.GENESIS_CHAIN_HASH,
                "cc".repeat(32),
                HashFormat.VERSION,
                true,
                NOW);
        when(policies.find()).thenReturn(new RetentionPolicy(1, NOW));
        when(events.findSeqsEligibleForArchive(any())).thenReturn(List.of(1L));
        when(events.lockBySeq(1)).thenReturn(Optional.of(archived));

        var result = new RetentionService(policies, events, Clock.fixed(NOW, ZoneOffset.UTC)).apply();

        assertThat(result.archivedCount()).isEqualTo(1);
        verify(events, never()).markArchived(anyLong(), any());
    }

    @Test
    @DisplayName("archival skips fields that are already redacted")
    void archiveSkipsAlreadyRedactedFields() {
        Stored live = stored(1, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":1,\"currency\":\"USD\"}");
        List<FieldCommitment> mixed =
                List.of(live.fields().get(0).redact(), live.fields().get(1));
        when(policies.find()).thenReturn(new RetentionPolicy(1, NOW));
        when(events.findSeqsEligibleForArchive(any())).thenReturn(List.of(1L));
        when(events.lockBySeq(1)).thenReturn(Optional.of(live.record()));
        when(events.findCommitments(1)).thenReturn(mixed);

        new RetentionService(policies, events, Clock.fixed(NOW, ZoneOffset.UTC)).apply();

        verify(events).redactCommitment(1, live.fields().get(1).path());
        verify(events, never()).redactCommitment(1, live.fields().get(0).path());
        verify(events).markArchived(eq(1L), any());
    }

    @Test
    @DisplayName("redaction that cannot reload the row afterwards is not found")
    void redactReloadMissingIsNotFound() {
        Stored stored = stored(1, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":1}");
        when(events.lockBySeq(1)).thenReturn(Optional.of(stored.record()));
        when(events.findCommitments(1)).thenReturn(stored.fields());
        when(events.findBySeq(1)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> new RedactionService(events).redact(1, List.of("/amount")))
                .isInstanceOf(EventNotFoundException.class);
    }

    @Test
    @DisplayName("an unknown export cannot be regenerated")
    void regenerateMissingExportIsNotFound() {
        UUID id = UUID.fromString("11111111-1111-1111-1111-111111111111");
        when(exports.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> new ExportService(events, exports, Clock.fixed(NOW, ZoneOffset.UTC)).regenerate(id))
                .isInstanceOf(ExportNotFoundException.class);
    }

    @Test
    @DisplayName("an invalid export range is rejected")
    void exportRejectsInvalidRange() {
        ExportService service = new ExportService(events, exports, Clock.fixed(NOW, ZoneOffset.UTC));

        assertThatThrownBy(() -> service.create(0, 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.create(3, 1)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("an empty log is a clean compliance report")
    void emptyLogComplianceReportIsClean() {
        when(events.latestSeq()).thenReturn(0L);
        when(policies.find()).thenReturn(new RetentionPolicy(365, NOW));
        when(events.countEligibleUnarchived(any())).thenReturn(0L);
        when(events.countArchived()).thenReturn(0L);
        when(events.countRedactedFields()).thenReturn(0L);
        when(events.countEventsWithRedaction()).thenReturn(0L);
        when(events.countEvents()).thenReturn(0L);
        when(events.countByEventType()).thenReturn(List.of());

        var report = new ComplianceService(
                        new ChainVerificationService(events, new PayloadCommitter()),
                        events,
                        policies,
                        Clock.fixed(NOW, ZoneOffset.UTC))
                .report();

        assertThat(report.chain().recordsChecked()).isZero();
        assertThat(report.retention().compliant()).isTrue();
    }

    @Test
    @DisplayName("eligible unarchived rows make retention non-compliant")
    void eligibleUnarchivedRowsAreNonCompliant() {
        when(events.latestSeq()).thenReturn(0L);
        when(policies.find()).thenReturn(new RetentionPolicy(365, NOW));
        when(events.countEligibleUnarchived(any())).thenReturn(2L);
        when(events.countArchived()).thenReturn(0L);
        when(events.countRedactedFields()).thenReturn(0L);
        when(events.countEventsWithRedaction()).thenReturn(0L);
        when(events.countEvents()).thenReturn(0L);
        when(events.countByEventType()).thenReturn(List.of());

        var report = new ComplianceService(
                        new ChainVerificationService(events, new PayloadCommitter()),
                        events,
                        policies,
                        Clock.fixed(NOW, ZoneOffset.UTC))
                .report();

        assertThat(report.retention().compliant()).isFalse();
        assertThat(report.retention().eligibleUnarchived()).isEqualTo(2L);
    }

    @Test
    @DisplayName("a unique-constraint collision on insert is a duplicate event")
    void appendMapsDuplicateKeyToDuplicateEvent() {
        PayloadCommitter committer = new PayloadCommitter();
        AuditEventService service = new AuditEventService(events, committer, Clock.fixed(NOW, ZoneOffset.UTC));
        UUID eventId = UUID.fromString("11111111-1111-1111-1111-111111111111");
        when(events.lockChainHead()).thenReturn(new ChainHead(0, HashFormat.GENESIS_CHAIN_HASH));
        when(events.existsByEventId(eventId)).thenReturn(false);
        doThrow(new DuplicateKeyException("dup")).when(events).insert(any());

        assertThatThrownBy(() -> service.append(new NewAuditEvent(
                        eventId,
                        "account.updated",
                        "user-1",
                        "account",
                        "acc-1",
                        NOW,
                        CanonicalJson.parse("{\"amount\":1}"))))
                .isInstanceOf(DuplicateEventException.class);
    }

    @Test
    @DisplayName("fetching a missing sequence is not found")
    void findBySeqMissingIsNotFound() {
        when(events.findBySeq(9)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> new AuditEventService(events, new PayloadCommitter(), Clock.systemUTC()).findBySeq(9))
                .isInstanceOf(EventNotFoundException.class);
    }

    @Test
    @DisplayName("blank filter values are treated as absent")
    void blankQueryFiltersAreIgnored() {
        AuditProperties properties = new AuditProperties(
                new AuditProperties.Payload(8, 256, 65536, 8192), new AuditProperties.Query(50, 200));
        when(events.findPage(any(), eq(51))).thenReturn(List.of());

        new AuditEventQueryService(events, properties).list(new AuditEventQuery(null, "  ", "", null, null, null));

        verify(events).findPage(new AuditEventQuery(null, null, null, null, null, null), 51);
    }

    @Test
    @DisplayName("page size null or below 1 falls back to the default")
    void pageSizeClampsNullAndNonPositive() {
        AuditProperties.Query query = new AuditProperties.Query(50, 200);

        assertThat(query.resolvePageSize(null)).isEqualTo(50);
        assertThat(query.resolvePageSize(0)).isEqualTo(50);
        assertThat(query.resolvePageSize(999)).isEqualTo(200);
    }

    private static Stored stored(long seq, String previous, String payloadJson) {
        var payload = CanonicalJson.parse(payloadJson);
        CommittedPayload committed = new PayloadCommitter().commit(payload);
        AuditEventHeader header = header();
        byte[] content = EventHasher.contentHash(header, Hex.decode(committed.payloadRootHex()));
        byte[] chain = EventHasher.chainHash(Hex.decode(previous), content);
        return new Stored(
                new AuditRecord(
                        seq,
                        header,
                        CanonicalJson.canonicalString(payload),
                        committed.payloadRootHex(),
                        Hex.encode(content),
                        previous,
                        Hex.encode(chain),
                        HashFormat.VERSION,
                        false,
                        null),
                committed.fields());
    }

    private record Stored(AuditRecord record, List<FieldCommitment> fields) {}

    private static AuditEventHeader header() {
        return new AuditEventHeader(
                UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
                "account.updated",
                "user-1",
                "account",
                "acc-1",
                Instant.parse("2026-01-01T00:00:00Z"),
                Instant.parse("2026-01-01T00:00:01Z"));
    }
}

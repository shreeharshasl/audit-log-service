package com.auditlog.hashing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class EventHasherTest {

    private static final UUID EVENT_ID = UUID.fromString("6f1b7d8e-3a2c-4f55-9d21-0c8a7b6e5f40");
    private static final Instant OCCURRED = Instant.parse("2026-03-01T10:15:30.123456Z");
    private static final Instant RECORDED = Instant.parse("2026-03-01T10:15:30.500000Z");

    private static AuditEventHeader header() {
        return new AuditEventHeader(EVENT_ID, "RECORD_UPDATED", "user-42", "ACCOUNT", "acct-9911", OCCURRED, RECORDED);
    }

    private static byte[] payloadRoot() {
        return new PayloadCommitter()
                .commit(CanonicalJson.parse("{\"field\":\"value\"}")).fields().stream()
                        .findFirst()
                        .map(f -> PayloadCommitter.payloadRoot(java.util.List.of(f)))
                        .orElseThrow();
    }

    @Test
    @DisplayName("the content hash changes when any header field changes")
    void contentHashCoversEveryHeaderField() {
        byte[] root = payloadRoot();
        byte[] baseline = EventHasher.contentHash(header(), root);

        assertThat(EventHasher.contentHash(
                        new AuditEventHeader(
                                EVENT_ID, "RECORD_DELETED", "user-42", "ACCOUNT", "acct-9911", OCCURRED, RECORDED),
                        root))
                .isNotEqualTo(baseline);
        assertThat(EventHasher.contentHash(
                        new AuditEventHeader(
                                EVENT_ID, "RECORD_UPDATED", "user-99", "ACCOUNT", "acct-9911", OCCURRED, RECORDED),
                        root))
                .isNotEqualTo(baseline);
        assertThat(EventHasher.contentHash(
                        new AuditEventHeader(
                                EVENT_ID, "RECORD_UPDATED", "user-42", "CUSTOMER", "acct-9911", OCCURRED, RECORDED),
                        root))
                .isNotEqualTo(baseline);
        assertThat(EventHasher.contentHash(
                        new AuditEventHeader(
                                EVENT_ID, "RECORD_UPDATED", "user-42", "ACCOUNT", "acct-0000", OCCURRED, RECORDED),
                        root))
                .isNotEqualTo(baseline);
        assertThat(EventHasher.contentHash(
                        new AuditEventHeader(
                                EVENT_ID,
                                "RECORD_UPDATED",
                                "user-42",
                                "ACCOUNT",
                                "acct-9911",
                                OCCURRED.plusMillis(1),
                                RECORDED),
                        root))
                .isNotEqualTo(baseline);
        assertThat(EventHasher.contentHash(
                        new AuditEventHeader(
                                EVENT_ID,
                                "RECORD_UPDATED",
                                "user-42",
                                "ACCOUNT",
                                "acct-9911",
                                OCCURRED,
                                RECORDED.plusMillis(1)),
                        root))
                .isNotEqualTo(baseline);
    }

    @Test
    @DisplayName("the content hash changes when the payload root changes")
    void contentHashCoversPayload() {
        byte[] rootA = sha("payload-a");
        byte[] rootB = sha("payload-b");

        assertThat(EventHasher.contentHash(header(), rootA)).isNotEqualTo(EventHasher.contentHash(header(), rootB));
    }

    @Test
    @DisplayName("the same header and payload root always hash the same")
    void contentHashIsDeterministic() {
        byte[] root = payloadRoot();

        assertThat(EventHasher.contentHash(header(), root)).isEqualTo(EventHasher.contentHash(header(), root));
    }

    @Test
    @DisplayName("a chain hash depends on both its predecessor and its own content")
    void chainHashCoversBothInputs() {
        byte[] content = EventHasher.contentHash(header(), payloadRoot());
        byte[] genesis = HashFormat.genesisChainHash();
        byte[] baseline = EventHasher.chainHash(genesis, content);

        byte[] otherPredecessor = new byte[32];
        otherPredecessor[31] = 1;

        assertThat(EventHasher.chainHash(otherPredecessor, content)).isNotEqualTo(baseline);
        assertThat(EventHasher.chainHash(genesis, EventHasher.contentHash(header(), payloadRoot())))
                .isNotEqualTo(baseline);
    }

    @Test
    @DisplayName("altering an early record changes every chain hash after it")
    void tamperingPropagatesAlongTheChain() {
        byte[] content1 = sha("record-1");
        byte[] content2 = sha("record-2");
        byte[] content3 = sha("record-3");

        byte[] honest1 = EventHasher.chainHash(HashFormat.genesisChainHash(), content1);
        byte[] honest2 = EventHasher.chainHash(honest1, content2);
        byte[] honest3 = EventHasher.chainHash(honest2, content3);

        byte[] tampered1 = EventHasher.chainHash(HashFormat.genesisChainHash(), sha("record-1-altered"));
        byte[] tampered2 = EventHasher.chainHash(tampered1, content2);
        byte[] tampered3 = EventHasher.chainHash(tampered2, content3);

        assertThat(tampered1).isNotEqualTo(honest1);
        assertThat(tampered2).isNotEqualTo(honest2);
        assertThat(tampered3).isNotEqualTo(honest3);
    }

    @Test
    @DisplayName("chain inputs must be full-width digests")
    void rejectsShortChainInputs() {
        assertThatThrownBy(() -> EventHasher.chainHash(new byte[16], new byte[32]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32-byte");
    }

    @Test
    @DisplayName("timestamps enter the hash as epoch microseconds")
    void convertsTimestampsToMicros() {
        assertThat(EventHasher.toEpochMicros(Instant.parse("1970-01-01T00:00:00Z")))
                .isZero();
        assertThat(EventHasher.toEpochMicros(Instant.parse("1970-01-01T00:00:01.000001Z")))
                .isEqualTo(1_000_001L);
        assertThat(EventHasher.toEpochMicros(Instant.parse("2026-03-01T10:15:30.123456Z")))
                .isEqualTo(1772360130123456L);
    }

    @Test
    @DisplayName("sub-microsecond precision is truncated, matching what PostgreSQL can store")
    void truncatesBelowMicrosecondPrecision() {
        assertThat(EventHasher.toEpochMicros(Instant.parse("2026-03-01T10:15:30.123456789Z")))
                .isEqualTo(EventHasher.toEpochMicros(Instant.parse("2026-03-01T10:15:30.123456Z")));
    }

    @Test
    @DisplayName("every header field is required, because all of them are hashed")
    void rejectsMissingHeaderFields() {
        assertThatThrownBy(() -> new AuditEventHeader(null, "TYPE", "actor", "RESOURCE", "id", OCCURRED, RECORDED))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("eventId");
    }

    private static byte[] sha(String value) {
        return HashBuilder.withTag(DomainTag.CONTENT).field(value).build();
    }
}

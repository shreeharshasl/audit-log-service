package com.auditlog.hashing;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class BundleVerifierTest {

    private final BundleVerifier verifier = new BundleVerifier();

    @Test
    @DisplayName("an honest two-record bundle verifies clean")
    void honestBundleIsIntact() {
        ExportedRecord first = ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":100}");
        ExportedRecord second = ExportTestRecords.record(2, first.chainHashHex(), "{\"amount\":200}");

        BundleVerifier.Result result = verifier.verify(ExportTestRecords.bundle(first, second));

        assertThat(result.intact()).isTrue();
        assertThat(result.recordsChecked()).isEqualTo(2);
        assertThat(result.checks()).isEmpty();
    }

    @Test
    @DisplayName("a fully redacted archived record still verifies, because salts are not in the hashes")
    void redactedRecordVerifies() {
        ExportedRecord archived = ExportTestRecords.record(
                1, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":100,\"currency\":\"USD\"}", true);

        BundleVerifier.Result result = verifier.verify(ExportTestRecords.bundle(archived));

        assertThat(result.intact()).isTrue();
        assertThat(archived.canonicalPayload()).isEqualTo("{}");
        assertThat(archived.commitments()).allMatch(FieldCommitment::redacted);
    }

    @Test
    @DisplayName("editing a payload value in the bundle is detected")
    void tamperedPayloadIsDetected() {
        ExportedRecord honest = ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":100}");
        ExportedRecord tampered = new ExportedRecord(
                honest.seq(),
                honest.header(),
                "{\"amount\":999}",
                honest.payloadRootHex(),
                honest.contentHashHex(),
                honest.previousChainHashHex(),
                honest.chainHashHex(),
                honest.hashVersion(),
                honest.archived(),
                honest.commitments());

        BundleVerifier.Result result = verifier.verify(ExportTestRecords.bundle(tampered));

        assertThat(result.intact()).isFalse();
        assertThat(result.checks())
                .extracting(BundleVerifier.Check::type)
                .contains(BundleVerifier.Check.Type.FIELD_COMMITMENT_INVALID);
    }

    @Test
    @DisplayName("a claimed manifest that does not match the records is detected")
    void tamperedManifestIsDetected() {
        ExportedRecord record = ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":100}");
        ExportBundle bundle = new ExportBundle(HashFormat.VERSION, 1, 1, "ff".repeat(32), List.of(record));

        BundleVerifier.Result result = verifier.verify(bundle);

        assertThat(result.intact()).isFalse();
        assertThat(result.checks())
                .extracting(BundleVerifier.Check::type)
                .contains(BundleVerifier.Check.Type.MANIFEST_MISMATCH);
    }

    @Test
    @DisplayName("a missing sequence in the claimed range is unauthorized deletion")
    void missingSequenceIsUnauthorizedArchive() {
        ExportedRecord first = ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":100}");
        ExportBundle bundle = new ExportBundle(
                HashFormat.VERSION,
                1,
                2,
                Hex.encode(ExportHasher.manifestHash(HashFormat.VERSION, 1, 1, List.of(first.toLink()))),
                List.of(first));

        BundleVerifier.Result result = verifier.verify(bundle);

        assertThat(result.intact()).isFalse();
        assertThat(result.checks())
                .extracting(BundleVerifier.Check::type)
                .contains(BundleVerifier.Check.Type.UNAUTHORIZED_ARCHIVE, BundleVerifier.Check.Type.MANIFEST_MISMATCH);
    }

    @Test
    @DisplayName("a hole between two exported sequences is unauthorized deletion")
    void gapBetweenRecordsIsUnauthorizedArchive() {
        ExportedRecord first = ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":100}");
        ExportedRecord third = ExportTestRecords.record(3, first.chainHashHex(), "{\"amount\":300}");
        ExportBundle bundle = new ExportBundle(HashFormat.VERSION, 1, 3, "ff".repeat(32), List.of(first, third));

        BundleVerifier.Result result = verifier.verify(bundle);

        assertThat(result.intact()).isFalse();
        assertThat(result.checks())
                .extracting(BundleVerifier.Check::type)
                .contains(BundleVerifier.Check.Type.UNAUTHORIZED_ARCHIVE);
    }

    @Test
    @DisplayName("editing a header field is caught by the content hash")
    void tamperedHeaderIsDetected() {
        ExportedRecord honest = ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":100}");
        AuditEventHeader altered = new AuditEventHeader(
                honest.header().eventId(),
                "account.deleted",
                honest.header().actorId(),
                honest.header().resourceType(),
                honest.header().resourceId(),
                honest.header().occurredAt(),
                honest.header().recordedAt());
        ExportedRecord tampered = new ExportedRecord(
                honest.seq(),
                altered,
                honest.canonicalPayload(),
                honest.payloadRootHex(),
                honest.contentHashHex(),
                honest.previousChainHashHex(),
                honest.chainHashHex(),
                honest.hashVersion(),
                honest.archived(),
                honest.commitments());

        BundleVerifier.Result result = verifier.verify(ExportTestRecords.bundle(tampered));

        assertThat(result.intact()).isFalse();
        assertThat(result.checks())
                .extracting(BundleVerifier.Check::type)
                .contains(
                        BundleVerifier.Check.Type.CONTENT_HASH_MISMATCH, BundleVerifier.Check.Type.CHAIN_HASH_MISMATCH);
    }

    @Test
    @DisplayName("an unsupported hash version is reported")
    void hashVersionMismatchIsDetected() {
        ExportedRecord record = ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":100}");
        ExportBundle bundle = new ExportBundle(99, 1, 1, record.chainHashHex(), List.of(record));

        BundleVerifier.Result result = verifier.verify(bundle);

        assertThat(result.intact()).isFalse();
        assertThat(result.checks())
                .extracting(BundleVerifier.Check::type)
                .contains(BundleVerifier.Check.Type.HASH_VERSION_MISMATCH, BundleVerifier.Check.Type.MANIFEST_MISMATCH);
    }

    @Test
    @DisplayName("a slice that does not include seq 1 cannot check the genesis link and still verifies")
    void rangeNotStartingAtGenesisSkipsPredecessorCheck() {
        ExportedRecord first = ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":100}");
        ExportedRecord second = ExportTestRecords.record(2, first.chainHashHex(), "{\"amount\":200}");
        ExportBundle slice = new ExportBundle(
                HashFormat.VERSION,
                2,
                2,
                Hex.encode(ExportHasher.manifestHash(HashFormat.VERSION, 2, 2, List.of(second.toLink()))),
                List.of(second));

        assertThat(verifier.verify(slice).intact()).isTrue();
    }

    @Test
    @DisplayName("a broken predecessor pointer is detected when the previous record is in the bundle")
    void brokenLinkIsDetected() {
        ExportedRecord first = ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":100}");
        ExportedRecord second = ExportTestRecords.record(2, first.chainHashHex(), "{\"amount\":200}");
        ExportedRecord broken = new ExportedRecord(
                second.seq(),
                second.header(),
                second.canonicalPayload(),
                second.payloadRootHex(),
                second.contentHashHex(),
                "ee".repeat(32),
                second.chainHashHex(),
                second.hashVersion(),
                second.archived(),
                second.commitments());

        BundleVerifier.Result result = verifier.verify(ExportTestRecords.bundle(first, broken));

        assertThat(result.intact()).isFalse();
        assertThat(result.checks())
                .extracting(BundleVerifier.Check::type)
                .contains(BundleVerifier.Check.Type.BROKEN_LINK, BundleVerifier.Check.Type.CHAIN_HASH_MISMATCH);
    }

    @Test
    @DisplayName("commitments that do not reproduce the payload root are detected")
    void payloadRootMismatchIsDetected() {
        ExportedRecord honest = ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":100}");
        ExportedRecord tampered = new ExportedRecord(
                honest.seq(),
                honest.header(),
                honest.canonicalPayload(),
                "ab".repeat(32),
                honest.contentHashHex(),
                honest.previousChainHashHex(),
                honest.chainHashHex(),
                honest.hashVersion(),
                honest.archived(),
                honest.commitments());

        BundleVerifier.Result result = verifier.verify(ExportTestRecords.bundle(tampered));

        assertThat(result.intact()).isFalse();
        assertThat(result.checks())
                .extracting(BundleVerifier.Check::type)
                .contains(
                        BundleVerifier.Check.Type.PAYLOAD_ROOT_MISMATCH,
                        BundleVerifier.Check.Type.CONTENT_HASH_MISMATCH);
    }

    @Test
    @DisplayName("a payload that is no longer canonical JSON is detected")
    void nonCanonicalPayloadIsDetected() {
        ExportedRecord honest = ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":100}");
        ExportedRecord tampered = new ExportedRecord(
                honest.seq(),
                honest.header(),
                "{",
                honest.payloadRootHex(),
                honest.contentHashHex(),
                honest.previousChainHashHex(),
                honest.chainHashHex(),
                honest.hashVersion(),
                honest.archived(),
                honest.commitments());

        BundleVerifier.Result result = verifier.verify(ExportTestRecords.bundle(tampered));

        assertThat(result.intact()).isFalse();
        assertThat(result.checks())
                .extracting(BundleVerifier.Check::type)
                .contains(BundleVerifier.Check.Type.FIELD_COMMITMENT_INVALID);
    }
}

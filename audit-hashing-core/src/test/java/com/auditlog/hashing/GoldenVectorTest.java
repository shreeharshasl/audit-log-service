package com.auditlog.hashing;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.auditlog.hashing.PayloadLeaf.LeafKind;

/**
 * Frozen expected outputs for hash format v1.
 *
 * <p>These values are the format. Any change to canonicalization, framing, domain tags or field
 * ordering will break these tests, which is the entire point: silently changing the hash
 * construction would invalidate every record ever written and would otherwise only surface much
 * later as an unexplained chain break in production.
 *
 * <p>If a change here is intentional, it requires a new {@link HashFormat#VERSION} and a documented
 * migration, not an edit to these constants.
 */
class GoldenVectorTest {

    private static final String SALT_A = "00".repeat(31) + "01";
    private static final String SALT_B = "00".repeat(31) + "02";
    private static final String SALT_C = "ff".repeat(32);

    private static final String PAYLOAD =
            "{\"amount\":250,\"account\":{\"number\":\"ACC-9911\",\"type\":\"CHECKING\"}}";

    private static final String COMMITMENT_ACCOUNT_NUMBER =
            "9d83ed57ff9f13aa540e8eee283926a0d41cf3ab89d2885804a47c26b32eb48d";
    private static final String COMMITMENT_ACCOUNT_TYPE =
            "019dee65b54685b1f599465a1d106273af21bb6275bfddaa9fa0dbcd23403d8e";
    private static final String COMMITMENT_AMOUNT = "2b3c3cd10d2e867eab2fb67d5f1bb3f4d1e671e7b0a2a63b5b200908ed4c5f54";
    private static final String PAYLOAD_ROOT = "1c980c9652751495540230089e339210f5477e3d55fe1c883dad975351e3fa31";
    private static final String CONTENT_HASH = "d0653e221b30d5dd4e81d0d9878a6b35e21a9ad90f20d342a1de648b66172c04";
    private static final String CHAIN_HASH_FIRST = "ab7f6cca8619a60bebe0e88b2c0994b0303745d739b8d7d312fb702256d9b828";
    private static final String CHAIN_HASH_SECOND = "25db967413a5908607870a62c8bf55ad377a1e912f9b569924cbdca3ace2e362";

    @Test
    @DisplayName("canonical form of the reference payload is byte-stable")
    void canonicalFormIsFrozen() {
        assertThat(CanonicalJson.canonicalString(CanonicalJson.parse(PAYLOAD)))
                .isEqualTo("{\"account\":{\"number\":\"ACC-9911\",\"type\":\"CHECKING\"},\"amount\":250}");
    }

    @Test
    @DisplayName("flattening the reference payload yields the expected paths and values")
    void flatteningIsFrozen() {
        List<PayloadLeaf> leaves = new PayloadFlattener().flatten(CanonicalJson.parse(PAYLOAD));

        assertThat(leaves)
                .extracting(PayloadLeaf::path, PayloadLeaf::canonicalValue)
                .containsExactly(
                        org.assertj.core.api.Assertions.tuple("/account/number", "\"ACC-9911\""),
                        org.assertj.core.api.Assertions.tuple("/account/type", "\"CHECKING\""),
                        org.assertj.core.api.Assertions.tuple("/amount", "250"));
    }

    @Test
    @DisplayName("field commitments under known salts are byte-stable")
    void commitmentsAreFrozen() {
        assertThat(Hex.encode(PayloadCommitter.commitmentOf("/account/number", Hex.decode(SALT_A), "\"ACC-9911\"")))
                .isEqualTo(COMMITMENT_ACCOUNT_NUMBER);
        assertThat(Hex.encode(PayloadCommitter.commitmentOf("/account/type", Hex.decode(SALT_B), "\"CHECKING\"")))
                .isEqualTo(COMMITMENT_ACCOUNT_TYPE);
        assertThat(Hex.encode(PayloadCommitter.commitmentOf("/amount", Hex.decode(SALT_C), "250")))
                .isEqualTo(COMMITMENT_AMOUNT);
    }

    @Test
    @DisplayName("the payload root over known commitments is byte-stable")
    void payloadRootIsFrozen() {
        assertThat(Hex.encode(PayloadCommitter.payloadRoot(referenceFields()))).isEqualTo(PAYLOAD_ROOT);
    }

    @Test
    @DisplayName("the content hash of the reference record is byte-stable")
    void contentHashIsFrozen() {
        assertThat(Hex.encode(EventHasher.contentHash(referenceHeader(), Hex.decode(PAYLOAD_ROOT))))
                .isEqualTo(CONTENT_HASH);
    }

    @Test
    @DisplayName("chain hashes from genesis onward are byte-stable")
    void chainHashesAreFrozen() {
        byte[] first = EventHasher.chainHash(HashFormat.genesisChainHash(), Hex.decode(CONTENT_HASH));
        byte[] second = EventHasher.chainHash(first, Hex.decode(CONTENT_HASH));

        assertThat(Hex.encode(first)).isEqualTo(CHAIN_HASH_FIRST);
        assertThat(Hex.encode(second)).isEqualTo(CHAIN_HASH_SECOND);
    }

    @Test
    @DisplayName("the genesis value is 32 zero bytes")
    void genesisIsFrozen() {
        assertThat(HashFormat.GENESIS_CHAIN_HASH).isEqualTo("0".repeat(64));
        assertThat(Hex.encode(HashFormat.genesisChainHash())).isEqualTo(HashFormat.GENESIS_CHAIN_HASH);
    }

    @Test
    @DisplayName("the format version is 1")
    void versionIsFrozen() {
        assertThat(HashFormat.VERSION).isEqualTo(1);
    }

    private static List<FieldCommitment> referenceFields() {
        return List.of(
                new FieldCommitment("/account/number", LeafKind.STRING, SALT_A, COMMITMENT_ACCOUNT_NUMBER, false),
                new FieldCommitment("/account/type", LeafKind.STRING, SALT_B, COMMITMENT_ACCOUNT_TYPE, false),
                new FieldCommitment("/amount", LeafKind.INTEGER, SALT_C, COMMITMENT_AMOUNT, false));
    }

    private static AuditEventHeader referenceHeader() {
        return new AuditEventHeader(
                UUID.fromString("6f1b7d8e-3a2c-4f55-9d21-0c8a7b6e5f40"),
                "RECORD_UPDATED",
                "user-42",
                "ACCOUNT",
                "acct-9911",
                Instant.parse("2026-03-01T10:15:30.123456Z"),
                Instant.parse("2026-03-01T10:15:30.500000Z"));
    }
}

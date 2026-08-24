package com.auditlog.hashing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.auditlog.hashing.PayloadLeaf.LeafKind;

/**
 * The rejection paths.
 *
 * <p>Validation that is never exercised is validation that may not work. Each of these guards exists
 * to stop a malformed or hostile input from reaching the hash construction, so each one gets a test.
 */
class ValidationEdgeCaseTest {

    private static final Instant T = Instant.parse("2026-03-01T10:15:30Z");
    private static final UUID ID = UUID.fromString("6f1b7d8e-3a2c-4f55-9d21-0c8a7b6e5f40");

    @Test
    @DisplayName("every hashed header field is individually required")
    void headerRejectsEachMissingField() {
        assertThatThrownBy(() -> new AuditEventHeader(null, "T", "a", "R", "i", T, T))
                .hasMessageContaining("eventId");
        assertThatThrownBy(() -> new AuditEventHeader(ID, null, "a", "R", "i", T, T))
                .hasMessageContaining("eventType");
        assertThatThrownBy(() -> new AuditEventHeader(ID, "T", null, "R", "i", T, T))
                .hasMessageContaining("actorId");
        assertThatThrownBy(() -> new AuditEventHeader(ID, "T", "a", null, "i", T, T))
                .hasMessageContaining("resourceType");
        assertThatThrownBy(() -> new AuditEventHeader(ID, "T", "a", "R", null, T, T))
                .hasMessageContaining("resourceId");
        assertThatThrownBy(() -> new AuditEventHeader(ID, "T", "a", "R", "i", null, T))
                .hasMessageContaining("occurredAt");
        assertThatThrownBy(() -> new AuditEventHeader(ID, "T", "a", "R", "i", T, null))
                .hasMessageContaining("recordedAt");
    }

    @Test
    @DisplayName("a commitment must have a path and a value")
    void fieldCommitmentRejectsMissingParts() {
        assertThatThrownBy(() -> new FieldCommitment(null, LeafKind.STRING, "aa", "bb", false))
                .hasMessageContaining("path is required");
        assertThatThrownBy(() -> new FieldCommitment("/a", LeafKind.STRING, "aa", null, false))
                .hasMessageContaining("commitment is required");
        assertThatThrownBy(() -> new FieldCommitment("/a", LeafKind.STRING, null, "bb", false))
                .hasMessageContaining("missing its salt");
    }

    @Test
    @DisplayName("a redacted commitment exposes no salt bytes")
    void redactedCommitmentHasNoSalt() {
        FieldCommitment redacted = new FieldCommitment("/a", LeafKind.STRING, "aabb", "ccdd", false).redact();

        assertThat(redacted.saltBytes()).isNull();
        assertThat(redacted.redacted()).isTrue();
        assertThat(redacted.commitmentBytes()).isEqualTo(Hex.decode("ccdd"));
    }

    @Test
    @DisplayName("payload limits must all be positive")
    void payloadLimitsRejectNonPositiveValues() {
        assertThatThrownBy(() -> new PayloadLimits(0, 1, 1, 1)).hasMessageContaining("positive");
        assertThatThrownBy(() -> new PayloadLimits(1, 0, 1, 1)).hasMessageContaining("positive");
        assertThatThrownBy(() -> new PayloadLimits(1, 1, 0, 1)).hasMessageContaining("positive");
        assertThatThrownBy(() -> new PayloadLimits(1, 1, 1, 0)).hasMessageContaining("positive");
    }

    @Test
    @DisplayName("hex decoding rejects malformed input")
    void hexRejectsMalformedInput() {
        assertThatThrownBy(() -> Hex.decode("abc"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("even length");
        assertThatThrownBy(() -> Hex.decode("zz"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid hex character");
    }

    @Test
    @DisplayName("hex round-trips arbitrary bytes")
    void hexRoundTrips() {
        byte[] bytes = {0x00, 0x7f, (byte) 0x80, (byte) 0xff, 0x10};

        assertThat(Hex.decode(Hex.encode(bytes))).isEqualTo(bytes);
        assertThat(Hex.encode(bytes)).isEqualTo("007f80ff10");
    }

    @Test
    @DisplayName("a null byte array is distinguishable from an empty one")
    void hashBuilderDistinguishesNullBytes() {
        byte[] nullBytes =
                HashBuilder.withTag(DomainTag.CONTENT).field((byte[]) null).build();
        byte[] emptyBytes =
                HashBuilder.withTag(DomainTag.CONTENT).field(new byte[0]).build();

        assertThat(nullBytes).isNotEqualTo(emptyBytes);
    }

    @Test
    @DisplayName("chain hashing rejects an oversized content hash")
    void chainRejectsWrongWidthContentHash() {
        assertThatThrownBy(() -> EventHasher.chainHash(new byte[32], new byte[64]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32-byte");
    }

    @Test
    @DisplayName("a null payload is rejected before flattening")
    void flattenerRejectsNullPayload() {
        assertThatThrownBy(() -> new PayloadFlattener().flatten(null))
                .isInstanceOf(CanonicalJsonException.class)
                .hasMessageContaining("must be a JSON object");
        assertThatThrownBy(() -> new PayloadFlattener().flatten(CanonicalJson.parse("null")))
                .isInstanceOf(CanonicalJsonException.class)
                .hasMessageContaining("must be a JSON object");
    }

    @Test
    @DisplayName("canonicalizing a null node yields the null literal")
    void canonicalizesNullNode() {
        assertThat(CanonicalJson.canonicalString(null)).isEqualTo("null");
    }

    @Test
    @DisplayName("a JSON string can be canonicalized in one step")
    void canonicalizesFromString() {
        assertThat(CanonicalJson.canonicalize("{\"b\":1,\"a\":2}"))
                .isEqualTo("{\"a\":2,\"b\":1}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("a map can be converted and canonicalized")
    void canonicalizesFromMap() {
        assertThat(CanonicalJson.canonicalString(CanonicalJson.toNode(Map.of("b", 1, "a", 2))))
                .isEqualTo("{\"a\":2,\"b\":1}");
    }

    @Test
    @DisplayName("JSON Pointer escaping round-trips tilde and slash")
    void jsonPointerRoundTrips() {
        assertThat(JsonPointers.escape("a/b~c")).isEqualTo("a~1b~0c");
        assertThat(JsonPointers.unescape("a~1b~0c")).isEqualTo("a/b~c");
    }

    @Test
    @DisplayName("booleans and top-level scalars canonicalize correctly")
    void canonicalizesScalars() {
        assertThat(CanonicalJson.canonicalString(CanonicalJson.parse("true"))).isEqualTo("true");
        assertThat(CanonicalJson.canonicalString(CanonicalJson.parse("false"))).isEqualTo("false");
        assertThat(CanonicalJson.canonicalString(CanonicalJson.parse("42"))).isEqualTo("42");
        assertThat(CanonicalJson.canonicalString(CanonicalJson.parse("\"x\""))).isEqualTo("\"x\"");
    }

    @Test
    @DisplayName("an empty payload object commits to a single structural leaf")
    void handlesEmptyPayload() {
        List<PayloadLeaf> leaves = new PayloadFlattener().flatten(CanonicalJson.parse("{}"));

        assertThat(leaves).singleElement().satisfies(leaf -> {
            assertThat(leaf.path()).isEmpty();
            assertThat(leaf.kind()).isEqualTo(LeafKind.EMPTY_OBJECT);
        });
    }

    @Test
    @DisplayName("verifying against an empty commitment set flags every field as uncommitted")
    void verifyFlagsUncommittedFieldsWhenNothingIsStored() {
        var checks = new PayloadCommitter().verify(CanonicalJson.parse("{\"a\":1}"), List.of());

        assertThat(checks).singleElement().satisfies(c -> assertThat(c.status())
                .isEqualTo(PayloadCommitter.CommitmentCheck.Status.UNCOMMITTED_FIELD));
    }
}

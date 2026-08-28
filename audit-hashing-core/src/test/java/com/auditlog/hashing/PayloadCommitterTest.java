package com.auditlog.hashing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.auditlog.hashing.PayloadCommitter.CommitmentCheck;
import com.auditlog.hashing.PayloadCommitter.CommitmentCheck.Status;
import com.fasterxml.jackson.databind.JsonNode;

class PayloadCommitterTest {

    private final PayloadCommitter committer = new PayloadCommitter();

    private static JsonNode payload() {
        return CanonicalJson.parse("{\"account\":{\"number\":\"ACC-9911\",\"type\":\"CHECKING\"},\"amount\":250}");
    }

    @Test
    @DisplayName("every position gets a distinct salt")
    void saltsEveryFieldIndependently() {
        CommittedPayload committed = committer.commit(payload());

        assertThat(committed.fields()).hasSize(3);
        assertThat(committed.fields()).extracting(FieldCommitment::saltHex).doesNotHaveDuplicates();
        assertThat(committed.fields())
                .allSatisfy(f -> assertThat(Hex.decode(f.saltHex())).hasSize(PayloadCommitter.SALT_LENGTH));
    }

    @Test
    @DisplayName("the same payload committed twice yields different roots, because salts are fresh")
    void saltsMakeCommitmentsNonDeterministic() {
        assertThat(committer.commit(payload()).payloadRootHex())
                .isNotEqualTo(committer.commit(payload()).payloadRootHex());
    }

    @Test
    @DisplayName("an untouched payload verifies clean")
    void verifiesUnmodifiedPayload() {
        CommittedPayload committed = committer.commit(payload());

        List<CommitmentCheck> checks = committer.verify(payload(), committed.fields());

        assertThat(checks).allMatch(c -> c.status() == Status.VALID);
        assertThat(checks).noneMatch(CommitmentCheck::isViolation);
    }

    @Test
    @DisplayName("changing a field value is detected at that exact path")
    void detectsAlteredValue() {
        CommittedPayload committed = committer.commit(payload());
        JsonNode tampered =
                CanonicalJson.parse("{\"account\":{\"number\":\"ACC-0000\",\"type\":\"CHECKING\"},\"amount\":250}");

        List<CommitmentCheck> checks = committer.verify(tampered, committed.fields());

        assertThat(checks)
                .filteredOn(CommitmentCheck::isViolation)
                .singleElement()
                .satisfies(c -> {
                    assertThat(c.path()).isEqualTo("/account/number");
                    assertThat(c.status()).isEqualTo(Status.VALUE_ALTERED);
                });
    }

    @Test
    @DisplayName("removing a field is detected")
    void detectsRemovedField() {
        CommittedPayload committed = committer.commit(payload());
        JsonNode tampered = CanonicalJson.parse("{\"account\":{\"type\":\"CHECKING\"},\"amount\":250}");

        List<CommitmentCheck> checks = committer.verify(tampered, committed.fields());

        assertThat(checks)
                .filteredOn(CommitmentCheck::isViolation)
                .singleElement()
                .satisfies(c -> assertThat(c.status()).isEqualTo(Status.MISSING_FROM_PAYLOAD));
    }

    @Test
    @DisplayName("adding a field is detected")
    void detectsAddedField() {
        CommittedPayload committed = committer.commit(payload());
        JsonNode tampered = CanonicalJson.parse(
                "{\"account\":{\"number\":\"ACC-9911\",\"type\":\"CHECKING\"},\"amount\":250,\"extra\":\"x\"}");

        List<CommitmentCheck> checks = committer.verify(tampered, committed.fields());

        assertThat(checks)
                .filteredOn(CommitmentCheck::isViolation)
                .singleElement()
                .satisfies(c -> {
                    assertThat(c.path()).isEqualTo("/extra");
                    assertThat(c.status()).isEqualTo(Status.UNCOMMITTED_FIELD);
                });
    }

    @Test
    @DisplayName("swapping two values between paths is detected, because the path is inside the commitment")
    void detectsSwappedValues() {
        JsonNode original = CanonicalJson.parse("{\"a\":\"one\",\"b\":\"two\"}");
        CommittedPayload committed = committer.commit(original);
        JsonNode swapped = CanonicalJson.parse("{\"a\":\"two\",\"b\":\"one\"}");

        List<CommitmentCheck> checks = committer.verify(swapped, committed.fields());

        assertThat(checks).filteredOn(CommitmentCheck::isViolation).hasSize(2);
    }

    @Test
    @DisplayName("redaction leaves the payload root unchanged, which is the whole point of the scheme")
    void redactionPreservesPayloadRoot() {
        CommittedPayload committed = committer.commit(payload());
        byte[] rootBefore = PayloadCommitter.payloadRoot(committed.fields());

        List<FieldCommitment> afterRedaction = new ArrayList<>();
        for (FieldCommitment field : committed.fields()) {
            afterRedaction.add(field.path().equals("/account/number") ? field.redact() : field);
        }
        byte[] rootAfter = PayloadCommitter.payloadRoot(afterRedaction);

        assertThat(rootAfter).isEqualTo(rootBefore);
    }

    @Test
    @DisplayName("a redacted field reports as unverifiable rather than valid or broken")
    void redactedFieldsAreUnverifiable() {
        CommittedPayload committed = committer.commit(payload());
        List<FieldCommitment> fields = new ArrayList<>();
        for (FieldCommitment field : committed.fields()) {
            fields.add(field.path().equals("/account/number") ? field.redact() : field);
        }
        JsonNode redactedPayload = CanonicalJson.parse("{\"account\":{\"type\":\"CHECKING\"},\"amount\":250}");

        List<CommitmentCheck> checks = committer.verify(redactedPayload, fields);

        assertThat(checks).noneMatch(CommitmentCheck::isViolation);
        assertThat(checks)
                .filteredOn(c -> c.path().equals("/account/number"))
                .singleElement()
                .satisfies(c -> assertThat(c.status()).isEqualTo(Status.UNVERIFIABLE_REDACTED));
    }

    @Test
    @DisplayName("a redacted field cannot keep its salt, or the value stays brute-forceable")
    void redactedFieldMayNotRetainSalt() {
        assertThatThrownBy(() -> new FieldCommitment("/a", PayloadLeaf.LeafKind.STRING, "aabb", "ccdd", true))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("still carries its salt");
    }

    @Test
    @DisplayName("the payload root commits to the field count, so entries cannot be dropped")
    void payloadRootCoversFieldCount() {
        CommittedPayload committed = committer.commit(payload());
        List<FieldCommitment> subset = committed.fields().subList(0, 2);

        assertThat(PayloadCommitter.payloadRoot(subset)).isNotEqualTo(PayloadCommitter.payloadRoot(committed.fields()));
    }

    @Test
    @DisplayName("the payload root is independent of the order commitments arrive in")
    void payloadRootIsOrderIndependent() {
        CommittedPayload committed = committer.commit(payload());
        List<FieldCommitment> reversed = new ArrayList<>(committed.fields());
        java.util.Collections.reverse(reversed);

        assertThat(PayloadCommitter.payloadRoot(reversed)).isEqualTo(PayloadCommitter.payloadRoot(committed.fields()));
    }

    @Test
    @DisplayName("duplicate paths in a commitment set are rejected")
    void rejectsDuplicatePaths() {
        FieldCommitment field = new FieldCommitment("/a", PayloadLeaf.LeafKind.STRING, "aa", "bb", false);

        assertThatThrownBy(() -> PayloadCommitter.payloadRoot(List.of(field, field)))
                .isInstanceOf(CanonicalJsonException.class)
                .hasMessageContaining("duplicate commitment");
    }

    @Test
    @DisplayName("a fully redacted payload stored as {} is unverifiable, not an uncommitted empty object")
    void fullyRedactedEmptyPayloadIsNotAnUncommittedRoot() {
        CommittedPayload committed = committer.commit(payload());
        List<FieldCommitment> redacted =
                committed.fields().stream().map(FieldCommitment::redact).toList();

        List<CommitmentCheck> checks = committer.verify(CanonicalJson.parse("{}"), redacted);

        assertThat(checks).noneMatch(CommitmentCheck::isViolation);
        assertThat(checks).allMatch(c -> c.status() == Status.UNVERIFIABLE_REDACTED);
        assertThat(checks).hasSize(3);
    }

    @Test
    @DisplayName("an empty object left inside an array after redaction is residue, not a new field")
    void emptyObjectResidueInsideArrayIsNotUncommitted() {
        JsonNode original = CanonicalJson.parse("{\"items\":[{\"secret\":\"x\"}]}");
        CommittedPayload committed = committer.commit(original);
        List<FieldCommitment> redacted =
                committed.fields().stream().map(FieldCommitment::redact).toList();
        JsonNode after = PayloadRedactor.removePaths(original, List.of("/items/0/secret"));

        List<CommitmentCheck> checks = committer.verify(after, redacted);

        assertThat(checks).noneMatch(CommitmentCheck::isViolation);
        assertThat(CanonicalJson.canonicalString(after)).isEqualTo("{\"items\":[{}]}");
    }

    @Test
    @DisplayName("a null array slot left after redacting an element is residue, not a new field")
    void nullArrayResidueIsNotUncommitted() {
        JsonNode original = CanonicalJson.parse("{\"tags\":[\"a\"]}");
        CommittedPayload committed = committer.commit(original);
        List<FieldCommitment> redacted =
                committed.fields().stream().map(FieldCommitment::redact).toList();
        JsonNode after = PayloadRedactor.removePaths(original, List.of("/tags/0"));

        List<CommitmentCheck> checks = committer.verify(after, redacted);

        assertThat(checks).noneMatch(CommitmentCheck::isViolation);
        assertThat(CanonicalJson.canonicalString(after)).isEqualTo("{\"tags\":[null]}");
    }

    @Test
    @DisplayName("nulling a whole array object leaves an uncommitted null that is residue")
    void nulledArrayObjectIsResidue() {
        JsonNode original = CanonicalJson.parse("{\"items\":[{\"secret\":\"x\"}]}");
        CommittedPayload committed = committer.commit(original);
        List<FieldCommitment> redacted =
                committed.fields().stream().map(FieldCommitment::redact).toList();
        JsonNode after = PayloadRedactor.removePaths(original, List.of("/items/0"));

        List<CommitmentCheck> checks = committer.verify(after, redacted);

        assertThat(checks).noneMatch(CommitmentCheck::isViolation);
        assertThat(CanonicalJson.canonicalString(after)).isEqualTo("{\"items\":[null]}");
    }

    @Test
    @DisplayName("a null payload is not treated as a fully redacted empty object")
    void nullPayloadIsRejectedRatherThanFullyRedacted() {
        assertThatThrownBy(() -> committer.verify(null, List.of())).isInstanceOf(CanonicalJsonException.class);
    }

    @Test
    @DisplayName("an originally empty array that is still present after sibling redaction verifies")
    void originallyEmptyArrayIsNotResidueConfusion() {
        JsonNode original = CanonicalJson.parse("{\"amount\":1,\"tags\":[]}");
        CommittedPayload committed = committer.commit(original);
        List<FieldCommitment> fields = new java.util.ArrayList<>();
        for (FieldCommitment field : committed.fields()) {
            fields.add(field.path().equals("/amount") ? field.redact() : field);
        }
        JsonNode after = PayloadRedactor.removePaths(original, List.of("/amount"));

        List<CommitmentCheck> checks = committer.verify(after, fields);

        assertThat(checks).noneMatch(CommitmentCheck::isViolation);
    }

    @Test
    @DisplayName("an empty object with no stored commitments is an uncommitted root, not a redaction")
    void emptyObjectWithoutCommitmentsIsUncommitted() {
        List<CommitmentCheck> checks = committer.verify(CanonicalJson.parse("{}"), List.of());

        assertThat(checks).singleElement().satisfies(c -> {
            assertThat(c.path()).isEmpty();
            assertThat(c.status()).isEqualTo(Status.UNCOMMITTED_FIELD);
        });
    }

    @Test
    @DisplayName("an empty object still holding live commitments is missing values, not fully redacted")
    void emptyObjectWithLiveCommitmentsIsNotFullyRedacted() {
        CommittedPayload committed = committer.commit(payload());

        List<CommitmentCheck> checks = committer.verify(CanonicalJson.parse("{}"), committed.fields());

        assertThat(checks).filteredOn(CommitmentCheck::isViolation).isNotEmpty();
        assertThat(checks)
                .filteredOn(c -> c.status() == Status.MISSING_FROM_PAYLOAD)
                .hasSize(3);
    }

    @Test
    @DisplayName("an empty object that was never a committed child is an uncommitted field")
    void leftoverEmptyObjectWithoutStoredChildrenIsUncommitted() {
        CommittedPayload committed = committer.commit(CanonicalJson.parse("{\"a\":1}"));
        JsonNode withEmpty = CanonicalJson.parse("{\"a\":1,\"meta\":{}}");

        List<CommitmentCheck> checks = committer.verify(withEmpty, committed.fields());

        assertThat(checks)
                .filteredOn(c -> c.path().equals("/meta"))
                .singleElement()
                .satisfies(c -> assertThat(c.status()).isEqualTo(Status.UNCOMMITTED_FIELD));
    }

    @Test
    @DisplayName("a non-object payload cannot be treated as a fully redacted empty object")
    void nonObjectPayloadIsNotFullyRedacted() {
        CommittedPayload committed = committer.commit(payload());
        List<FieldCommitment> redacted =
                committed.fields().stream().map(FieldCommitment::redact).toList();

        assertThatThrownBy(() -> committer.verify(CanonicalJson.parse("[1]"), redacted))
                .isInstanceOf(CanonicalJsonException.class);
    }

    @Test
    @DisplayName("an uncommitted empty array is a new field, not redaction residue")
    void uncommittedEmptyArrayIsNotResidue() {
        CommittedPayload committed = committer.commit(CanonicalJson.parse("{\"a\":1}"));
        JsonNode withEmpty = CanonicalJson.parse("{\"a\":1,\"tags\":[]}");

        List<CommitmentCheck> checks = committer.verify(withEmpty, committed.fields());

        assertThat(checks)
                .filteredOn(c -> c.path().equals("/tags"))
                .singleElement()
                .satisfies(c -> assertThat(c.status()).isEqualTo(Status.UNCOMMITTED_FIELD));
    }
}

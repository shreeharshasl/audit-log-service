package com.auditlog.hashing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;

class PayloadRedactorTest {

    @Test
    @DisplayName("removing a nested field leaves siblings and does not leave an empty parent object")
    void removesNestedFieldAndPrunesEmptyParents() {
        JsonNode payload =
                CanonicalJson.parse("{\"account\":{\"number\":\"ACC-9911\",\"type\":\"CHECKING\"},\"amount\":250}");

        JsonNode redacted = PayloadRedactor.removePaths(payload, List.of("/account/number"));

        assertThat(CanonicalJson.canonicalString(redacted))
                .isEqualTo("{\"account\":{\"type\":\"CHECKING\"},\"amount\":250}");
    }

    @Test
    @DisplayName("removing every child of an object prunes that object rather than leaving {}")
    void prunesObjectThatWasNotOriginallyEmpty() {
        JsonNode payload = CanonicalJson.parse("{\"account\":{\"number\":\"ACC-9911\"},\"amount\":250}");

        JsonNode redacted = PayloadRedactor.removePaths(payload, List.of("/account/number"));

        assertThat(CanonicalJson.canonicalString(redacted)).isEqualTo("{\"amount\":250}");
    }

    @Test
    @DisplayName("an originally empty object is kept, because it is a committed leaf")
    void keepsOriginallyEmptyObjects() {
        JsonNode payload = CanonicalJson.parse("{\"amount\":250,\"note\":{}}");

        JsonNode redacted = PayloadRedactor.removePaths(payload, List.of("/amount"));

        assertThat(CanonicalJson.canonicalString(redacted)).isEqualTo("{\"note\":{}}");
    }

    @Test
    @DisplayName("redacting every field leaves an empty object rather than null")
    void fullyRedactedPayloadIsEmptyObject() {
        JsonNode payload = CanonicalJson.parse("{\"amount\":250}");

        JsonNode redacted = PayloadRedactor.removePaths(payload, List.of("/amount"));

        assertThat(CanonicalJson.canonicalString(redacted)).isEqualTo("{}");
    }

    @Test
    @DisplayName("array elements are replaced with null so later indexes keep their paths")
    void arrayElementsAreNulledNotCompacted() {
        JsonNode payload = CanonicalJson.parse("{\"tags\":[\"a\",\"b\",\"c\"]}");

        JsonNode redacted = PayloadRedactor.removePaths(payload, List.of("/tags/1"));

        assertThat(CanonicalJson.canonicalString(redacted)).isEqualTo("{\"tags\":[\"a\",null,\"c\"]}");
    }

    @Test
    @DisplayName("keys that contain slashes are addressed with RFC 6901 escaping")
    void escapedPointerTokens() {
        JsonNode payload = CanonicalJson.parse("{\"a/b\":\"secret\",\"ok\":true}");

        JsonNode redacted = PayloadRedactor.removePaths(payload, List.of("/a~1b"));

        assertThat(CanonicalJson.canonicalString(redacted)).isEqualTo("{\"ok\":true}");
    }

    @Test
    @DisplayName("removing a whole object redacts every nested field in one step")
    void removingParentRemovesNestedFields() {
        JsonNode payload =
                CanonicalJson.parse("{\"account\":{\"number\":\"ACC-9911\",\"type\":\"CHECKING\"},\"amount\":250}");

        JsonNode redacted = PayloadRedactor.removePaths(payload, List.of("/account"));

        assertThat(CanonicalJson.canonicalString(redacted)).isEqualTo("{\"amount\":250}");
    }

    @Test
    @DisplayName("a missing path is rejected rather than silently skipped")
    void missingPathIsRejected() {
        JsonNode payload = CanonicalJson.parse("{\"amount\":250}");

        assertThatThrownBy(() -> PayloadRedactor.removePaths(payload, List.of("/currency")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("/currency");
    }

    @Test
    @DisplayName("the document root cannot be redacted as a pointer")
    void rejectsRootPointer() {
        JsonNode payload = CanonicalJson.parse("{\"amount\":250}");

        assertThatThrownBy(() -> PayloadRedactor.removePaths(payload, List.of("/")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("document root");
    }

    @Test
    @DisplayName("pointers must start with a slash")
    void rejectsPointerWithoutSlash() {
        JsonNode payload = CanonicalJson.parse("{\"amount\":250}");

        assertThatThrownBy(() -> PayloadRedactor.removePaths(payload, List.of("amount")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("JSON Pointer");
    }

    @Test
    @DisplayName("an empty path list is rejected")
    void rejectsEmptyPathList() {
        JsonNode payload = CanonicalJson.parse("{\"amount\":250}");

        assertThatThrownBy(() -> PayloadRedactor.removePaths(payload, List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least one path");
    }

    @Test
    @DisplayName("a non-object payload cannot be redacted")
    void rejectsNonObjectPayload() {
        assertThatThrownBy(() -> PayloadRedactor.removePaths(CanonicalJson.parse("[1]"), List.of("/0")))
                .isInstanceOf(CanonicalJsonException.class)
                .hasMessageContaining("JSON object");
    }

    @Test
    @DisplayName("duplicate pointers are applied once")
    void duplicatePointersAreIdempotent() {
        JsonNode payload = CanonicalJson.parse("{\"amount\":250,\"currency\":\"USD\"}");

        JsonNode redacted = PayloadRedactor.removePaths(payload, List.of("/amount", "/amount"));

        assertThat(CanonicalJson.canonicalString(redacted)).isEqualTo("{\"currency\":\"USD\"}");
    }

    @Test
    @DisplayName("an originally empty array is kept")
    void keepsOriginallyEmptyArrays() {
        JsonNode payload = CanonicalJson.parse("{\"amount\":1,\"tags\":[]}");

        JsonNode redacted = PayloadRedactor.removePaths(payload, List.of("/amount"));

        assertThat(CanonicalJson.canonicalString(redacted)).isEqualTo("{\"tags\":[]}");
    }

    @Test
    @DisplayName("out-of-range array indexes are missing paths")
    void outOfRangeArrayIndexIsMissing() {
        JsonNode payload = CanonicalJson.parse("{\"tags\":[\"a\"]}");

        assertThatThrownBy(() -> PayloadRedactor.removePaths(payload, List.of("/tags/3")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("/tags/3");
    }

    @Test
    @DisplayName("a nested object inside an array has its remaining siblings preserved")
    void redactsInsideArrayObjects() {
        JsonNode payload = CanonicalJson.parse("{\"items\":[{\"secret\":\"x\",\"n\":1}]}");

        JsonNode redacted = PayloadRedactor.removePaths(payload, List.of("/items/0/secret"));

        assertThat(CanonicalJson.canonicalString(redacted)).isEqualTo("{\"items\":[{\"n\":1}]}");
    }

    @Test
    @DisplayName("a blank path is rejected")
    void rejectsBlankPath() {
        JsonNode payload = CanonicalJson.parse("{\"amount\":1}");

        assertThatThrownBy(() -> PayloadRedactor.removePaths(payload, List.of("  ")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("path is required");
    }

    @Test
    @DisplayName("a nested pointer through a scalar is a missing path")
    void nestedPointerThroughScalarIsMissing() {
        JsonNode payload = CanonicalJson.parse("{\"amount\":1}");

        assertThatThrownBy(() -> PayloadRedactor.removePaths(payload, List.of("/amount/extra")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("/amount/extra");
    }

    @Test
    @DisplayName("array indexes may not have leading zeros")
    void rejectsLeadingZeroArrayIndex() {
        JsonNode payload = CanonicalJson.parse("{\"tags\":[\"a\"]}");

        assertThatThrownBy(() -> PayloadRedactor.removePaths(payload, List.of("/tags/01")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("/tags/01");
    }

    @Test
    @DisplayName("null inputs are rejected")
    void rejectsNullInputs() {
        assertThatThrownBy(() -> PayloadRedactor.removePaths(null, List.of("/amount")))
                .isInstanceOf(CanonicalJsonException.class);
        assertThatThrownBy(() -> PayloadRedactor.removePaths(CanonicalJson.parse("{\"amount\":1}"), null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least one path");
    }

    @Test
    @DisplayName("a nested path through a missing parent is rejected")
    void nestedMissingParentIsRejected() {
        JsonNode payload = CanonicalJson.parse("{\"amount\":1}");

        assertThatThrownBy(() -> PayloadRedactor.removePaths(payload, List.of("/account/number")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("/account/number");
    }

    @Test
    @DisplayName("a trailing slash on an array path is a missing index")
    void emptyArrayIndexTokenIsMissing() {
        JsonNode payload = CanonicalJson.parse("{\"tags\":[\"a\"]}");

        assertThatThrownBy(() -> PayloadRedactor.removePaths(payload, List.of("/tags/")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("/tags/");
    }

    @Test
    @DisplayName("a negative array index is a missing path")
    void negativeArrayIndexIsMissing() {
        JsonNode payload = CanonicalJson.parse("{\"tags\":[\"a\"]}");

        assertThatThrownBy(() -> PayloadRedactor.removePaths(payload, List.of("/tags/-1")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("/tags/-1");
    }

    @Test
    @DisplayName("a non-numeric array index is a missing path")
    void nonNumericArrayIndexIsMissing() {
        JsonNode payload = CanonicalJson.parse("{\"tags\":[\"a\"]}");

        assertThatThrownBy(() -> PayloadRedactor.removePaths(payload, List.of("/tags/abc")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("/tags/abc");
    }

    @Test
    @DisplayName("a nested pointer through a missing array slot is a missing path")
    void nestedPointerThroughMissingArraySlotIsMissing() {
        JsonNode payload = CanonicalJson.parse("{\"items\":[{\"secret\":\"x\"}]}");

        assertThatThrownBy(() -> PayloadRedactor.removePaths(payload, List.of("/items/9/secret")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("/items/9/secret");
    }

    @Test
    @DisplayName("a nested pointer through a leading-zero array index is a missing path")
    void nestedLeadingZeroArrayIndexIsMissing() {
        JsonNode payload = CanonicalJson.parse("{\"items\":[{\"secret\":\"x\"}]}");

        assertThatThrownBy(() -> PayloadRedactor.removePaths(payload, List.of("/items/01/secret")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("/items/01/secret");
    }

    @Test
    @DisplayName("a pointer three levels through a scalar is a missing path")
    void pointerThroughScalarThenAnotherTokenIsMissing() {
        JsonNode payload = CanonicalJson.parse("{\"amount\":1}");

        assertThatThrownBy(() -> PayloadRedactor.removePaths(payload, List.of("/amount/x/y")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("/amount/x/y");
    }

    @Test
    @DisplayName("a null path in the list is rejected")
    void rejectsNullPathInList() {
        JsonNode payload = CanonicalJson.parse("{\"amount\":1}");

        assertThatThrownBy(() -> PayloadRedactor.removePaths(payload, java.util.Arrays.asList((String) null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("path is required");
    }

    @Test
    @DisplayName("redacting the last remaining array still leaves the originally empty sibling")
    void prunesEmptiedNestedContainersButKeepsOriginalEmptyArrays() {
        JsonNode payload = CanonicalJson.parse("{\"keep\":[],\"drop\":{\"n\":1}}");

        JsonNode redacted = PayloadRedactor.removePaths(payload, List.of("/drop/n"));

        assertThat(CanonicalJson.canonicalString(redacted)).isEqualTo("{\"keep\":[]}");
    }
}

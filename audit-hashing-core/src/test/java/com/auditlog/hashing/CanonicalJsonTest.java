package com.auditlog.hashing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class CanonicalJsonTest {

    @Test
    @DisplayName("object keys are sorted, so input order cannot change the hash")
    void sortsObjectKeys() {
        String a = CanonicalJson.canonicalString(CanonicalJson.parse("{\"b\":1,\"a\":2,\"c\":3}"));
        String b = CanonicalJson.canonicalString(CanonicalJson.parse("{\"c\":3,\"a\":2,\"b\":1}"));

        assertThat(a).isEqualTo("{\"a\":2,\"b\":1,\"c\":3}");
        assertThat(a).isEqualTo(b);
    }

    @Test
    @DisplayName("nested objects are sorted at every level")
    void sortsNestedKeys() {
        String result = CanonicalJson.canonicalString(
                CanonicalJson.parse("{\"z\":{\"y\":1,\"x\":2},\"a\":[3,{\"q\":1,\"p\":2}]}"));

        assertThat(result).isEqualTo("{\"a\":[3,{\"p\":2,\"q\":1}],\"z\":{\"x\":2,\"y\":1}}");
    }

    @Test
    @DisplayName("array order is preserved, because order is meaningful in an array")
    void preservesArrayOrder() {
        String result = CanonicalJson.canonicalString(CanonicalJson.parse("[3,1,2]"));

        assertThat(result).isEqualTo("[3,1,2]");
    }

    @Test
    @DisplayName("insignificant whitespace does not affect the canonical form")
    void ignoresWhitespace() {
        String spaced = CanonicalJson.canonicalString(CanonicalJson.parse("{\n  \"a\" :  1 ,\n  \"b\": [ 1, 2 ]\n}"));

        assertThat(spaced).isEqualTo("{\"a\":1,\"b\":[1,2]}");
    }

    @Test
    @DisplayName("strings use the two-character escapes where they exist")
    void escapesStringsMinimally() {
        assertThat(canonicalValueOf("quote \" here")).isEqualTo("\"quote \\\" here\"");
        assertThat(canonicalValueOf("back \\ slash")).isEqualTo("\"back \\\\ slash\"");
        assertThat(canonicalValueOf("tab\there")).isEqualTo("\"tab\\there\"");
        assertThat(canonicalValueOf("new\nline")).isEqualTo("\"new\\nline\"");
        assertThat(canonicalValueOf("ret\rurn")).isEqualTo("\"ret\\rurn\"");
        assertThat(canonicalValueOf("back\bspace")).isEqualTo("\"back\\bspace\"");
        assertThat(canonicalValueOf("form\ffeed")).isEqualTo("\"form\\ffeed\"");
    }

    private static String canonicalValueOf(String input) {
        String object = CanonicalJson.canonicalString(CanonicalJson.toNode(java.util.Map.of("v", input)));
        return object.substring("{\"v\":".length(), object.length() - 1);
    }

    @Test
    @DisplayName("forward slashes and non-ASCII are emitted literally, not escaped")
    void doesNotOverEscape() {
        String result = CanonicalJson.canonicalString(CanonicalJson.parse("{\"v\":\"a/b \u00e9 \u4e2d\"}"));

        assertThat(result).isEqualTo("{\"v\":\"a/b \u00e9 \u4e2d\"}");
    }

    @Test
    @DisplayName("control characters below 0x20 become \\u escapes")
    void escapesControlCharacters() {
        String result = CanonicalJson.canonicalString(CanonicalJson.parse("{\"v\":\"\\u0001\"}"));

        assertThat(result).isEqualTo("{\"v\":\"\\u0001\"}");
    }

    @Test
    @DisplayName("floating point numbers are rejected rather than silently canonicalized")
    void rejectsFloats() {
        assertThatThrownBy(() -> CanonicalJson.canonicalString(CanonicalJson.parse("{\"amount\":10.5}")))
                .isInstanceOf(CanonicalJsonException.class)
                .hasMessageContaining("floating point")
                .hasMessageContaining("/amount");
    }

    @Test
    @DisplayName("integers beyond the safe range are rejected so JSON consumers cannot lose precision")
    void rejectsUnsafeIntegers() {
        assertThatThrownBy(() -> CanonicalJson.canonicalString(CanonicalJson.parse("{\"n\":9007199254740992}")))
                .isInstanceOf(CanonicalJsonException.class)
                .hasMessageContaining("safe range");
    }

    @Test
    @DisplayName("the safe-range boundary itself is accepted")
    void acceptsSafeIntegerBoundary() {
        assertThat(CanonicalJson.canonicalString(CanonicalJson.parse("{\"n\":9007199254740991}")))
                .isEqualTo("{\"n\":9007199254740991}");
    }

    @Test
    @DisplayName("duplicate keys are rejected instead of resolving to last-wins")
    void rejectsDuplicateKeys() {
        assertThatThrownBy(() -> CanonicalJson.parse("{\"a\":1,\"a\":2}"))
                .isInstanceOf(CanonicalJsonException.class)
                .hasMessageContaining("Duplicate");
    }

    @Test
    @DisplayName("malformed JSON is rejected with a usable message")
    void rejectsMalformedJson() {
        assertThatThrownBy(() -> CanonicalJson.parse("{\"a\":"))
                .isInstanceOf(CanonicalJsonException.class)
                .hasMessageContaining("not valid JSON");
    }

    @Test
    @DisplayName("negative zero and plain zero canonicalize identically")
    void normalizesNegativeZero() {
        assertThat(CanonicalJson.canonicalString(CanonicalJson.parse("{\"n\":-0}")))
                .isEqualTo("{\"n\":0}");
    }
}

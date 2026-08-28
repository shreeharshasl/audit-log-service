package com.auditlog.hashing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.auditlog.hashing.PayloadLeaf.LeafKind;

class PayloadFlattenerTest {

    private final PayloadFlattener flattener = new PayloadFlattener();

    @Test
    @DisplayName("nested fields flatten to JSON Pointer paths in sorted order")
    void flattensToSortedPointerPaths() {
        List<PayloadLeaf> leaves =
                flattener.flatten(CanonicalJson.parse("{\"user\":{\"id\":\"u1\",\"admin\":true},\"amount\":250}"));

        assertThat(leaves).extracting(PayloadLeaf::path).containsExactly("/amount", "/user/admin", "/user/id");
    }

    @Test
    @DisplayName("array elements are indexed positionally")
    void indexesArrayElements() {
        List<PayloadLeaf> leaves = flattener.flatten(CanonicalJson.parse("{\"tags\":[\"a\",\"b\"]}"));

        assertThat(leaves).extracting(PayloadLeaf::path).containsExactly("/tags/0", "/tags/1");
    }

    @Test
    @DisplayName("empty containers are leaves, so they cannot be added or removed uncommitted")
    void treatsEmptyContainersAsLeaves() {
        List<PayloadLeaf> leaves = flattener.flatten(CanonicalJson.parse("{\"tags\":[],\"meta\":{}}"));

        assertThat(leaves)
                .extracting(PayloadLeaf::path, PayloadLeaf::kind)
                .containsExactly(
                        org.assertj.core.api.Assertions.tuple("/meta", LeafKind.EMPTY_OBJECT),
                        org.assertj.core.api.Assertions.tuple("/tags", LeafKind.EMPTY_ARRAY));
    }

    @Test
    @DisplayName("a string and an integer with the same text commit to different values")
    void distinguishesStringFromNumber() {
        String asString =
                flattener.flatten(CanonicalJson.parse("{\"v\":\"123\"}")).get(0).canonicalValue();
        String asNumber =
                flattener.flatten(CanonicalJson.parse("{\"v\":123}")).get(0).canonicalValue();

        assertThat(asString).isEqualTo("\"123\"");
        assertThat(asNumber).isEqualTo("123");
    }

    @Test
    @DisplayName("keys containing slashes are escaped so they cannot impersonate nesting")
    void escapesSlashesInKeys() {
        List<PayloadLeaf> ambiguous = flattener.flatten(CanonicalJson.parse("{\"a/b\":1}"));
        List<PayloadLeaf> nested = flattener.flatten(CanonicalJson.parse("{\"a\":{\"b\":1}}"));

        assertThat(ambiguous.get(0).path()).isEqualTo("/a~1b");
        assertThat(nested.get(0).path()).isEqualTo("/a/b");
    }

    @Test
    @DisplayName("null values are committed, not skipped")
    void commitsNulls() {
        List<PayloadLeaf> leaves = flattener.flatten(CanonicalJson.parse("{\"v\":null}"));

        assertThat(leaves).singleElement().satisfies(leaf -> {
            assertThat(leaf.kind()).isEqualTo(LeafKind.NULL);
            assertThat(leaf.canonicalValue()).isEqualTo("null");
        });
    }

    @Test
    @DisplayName("a non-object payload is rejected")
    void rejectsNonObjectPayload() {
        assertThatThrownBy(() -> flattener.flatten(CanonicalJson.parse("[1,2]")))
                .isInstanceOf(CanonicalJsonException.class)
                .hasMessageContaining("must be a JSON object");
    }

    @Test
    @DisplayName("nesting beyond the depth limit is rejected before hashing")
    void enforcesDepthLimit() {
        PayloadFlattener shallow = new PayloadFlattener(new PayloadLimits(2, 256, 65536, 8192));

        assertThatThrownBy(() -> shallow.flatten(CanonicalJson.parse("{\"a\":{\"b\":{\"c\":1}}}")))
                .isInstanceOf(CanonicalJsonException.class)
                .hasMessageContaining("depth limit");
    }

    @Test
    @DisplayName("too many fields is rejected before hashing")
    void enforcesLeafLimit() {
        PayloadFlattener narrow = new PayloadFlattener(new PayloadLimits(8, 2, 65536, 8192));

        assertThatThrownBy(() -> narrow.flatten(CanonicalJson.parse("{\"a\":1,\"b\":2,\"c\":3,\"d\":4}")))
                .isInstanceOf(CanonicalJsonException.class)
                .hasMessageContaining("limit of 2 fields");
    }

    @Test
    @DisplayName("an oversized payload is rejected before hashing")
    void enforcesSizeLimit() {
        PayloadFlattener tiny = new PayloadFlattener(new PayloadLimits(8, 256, 16, 8192));

        assertThatThrownBy(() -> tiny.flatten(CanonicalJson.parse("{\"key\":\"a fairly long value here\"}")))
                .isInstanceOf(CanonicalJsonException.class)
                .hasMessageContaining("limit is 16");
    }

    @Test
    @DisplayName("an oversized single string is rejected")
    void enforcesStringLengthLimit() {
        PayloadFlattener shortStrings = new PayloadFlattener(new PayloadLimits(8, 256, 65536, 4));

        assertThatThrownBy(() -> shortStrings.flatten(CanonicalJson.parse("{\"v\":\"abcdefgh\"}")))
                .isInstanceOf(CanonicalJsonException.class)
                .hasMessageContaining("limit is 4");
    }

    @Test
    @DisplayName("binary JSON nodes cannot be committed as payload fields")
    void rejectsBinaryNodes() {
        var root = (com.fasterxml.jackson.databind.node.ObjectNode) CanonicalJson.parse("{}");
        root.set("bin", com.fasterxml.jackson.databind.node.JsonNodeFactory.instance.binaryNode(new byte[] {1}));

        assertThatThrownBy(() -> flattener.flatten(root))
                .isInstanceOf(CanonicalJsonException.class)
                .hasMessageContaining("unsupported JSON node type");
    }

    @Test
    @DisplayName("a leaf's canonical value is the UTF-8 of the committed text")
    void valueBytesMatchCanonicalText() {
        PayloadLeaf leaf =
                flattener.flatten(CanonicalJson.parse("{\"v\":\"ab\"}")).get(0);

        assertThat(PayloadFlattener.valueBytes(leaf))
                .isEqualTo(leaf.canonicalValue().getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}

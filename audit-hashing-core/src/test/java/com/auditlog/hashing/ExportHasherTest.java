package com.auditlog.hashing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ExportHasherTest {

    private static final String CONTENT_A = "aa".repeat(32);
    private static final String CHAIN_A = "bb".repeat(32);
    private static final String CONTENT_B = "cc".repeat(32);
    private static final String CHAIN_B = "dd".repeat(32);

    @Test
    @DisplayName("the same links always produce the same manifest")
    void isDeterministic() {
        List<ExportLink> links = List.of(new ExportLink(1, CONTENT_A, CHAIN_A), new ExportLink(2, CONTENT_B, CHAIN_B));

        assertThat(ExportHasher.manifestHash(HashFormat.VERSION, 1, 2, links))
                .isEqualTo(ExportHasher.manifestHash(HashFormat.VERSION, 1, 2, links))
                .hasSize(32);
    }

    @Test
    @DisplayName("the manifest changes when a record's chain hash changes")
    void coversEachChainHash() {
        List<ExportLink> honest = List.of(new ExportLink(1, CONTENT_A, CHAIN_A));
        List<ExportLink> swapped = List.of(new ExportLink(1, CONTENT_A, CHAIN_B));

        assertThat(ExportHasher.manifestHash(HashFormat.VERSION, 1, 1, honest))
                .isNotEqualTo(ExportHasher.manifestHash(HashFormat.VERSION, 1, 1, swapped));
    }

    @Test
    @DisplayName("the manifest is not a content hash of the same bytes")
    void usesExportManifestDomainTag() {
        List<ExportLink> links = List.of(new ExportLink(1, CONTENT_A, CHAIN_A));
        byte[] manifest = ExportHasher.manifestHash(HashFormat.VERSION, 1, 1, links);
        byte[] asContent = HashBuilder.withTag(DomainTag.CONTENT)
                .int32(HashFormat.VERSION)
                .int64(1)
                .int64(1)
                .int32(1)
                .int64(1)
                .fixed(Hex.decode(CONTENT_A))
                .fixed(Hex.decode(CHAIN_A))
                .build();

        assertThat(manifest).isNotEqualTo(asContent);
    }

    @Test
    @DisplayName("a gap in the exported sequences is rejected rather than hashed")
    void rejectsNonContiguousLinks() {
        List<ExportLink> links = List.of(new ExportLink(1, CONTENT_A, CHAIN_A), new ExportLink(3, CONTENT_B, CHAIN_B));

        assertThatThrownBy(() -> ExportHasher.manifestHash(HashFormat.VERSION, 1, 2, links))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("contiguous");
    }

    @Test
    @DisplayName("an empty export cannot produce a manifest")
    void rejectsEmptyExport() {
        assertThatThrownBy(() -> ExportHasher.manifestHash(HashFormat.VERSION, 1, 1, List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least one");
    }

    @Test
    @DisplayName("only the current hash format version is accepted")
    void rejectsUnknownHashVersion() {
        assertThatThrownBy(() -> ExportHasher.manifestHash(99, 1, 1, List.of(new ExportLink(1, CONTENT_A, CHAIN_A))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("hash version");
    }

    @Test
    @DisplayName("fromSeq must be a real sequence number")
    void rejectsInvalidRange() {
        assertThatThrownBy(() -> ExportHasher.manifestHash(
                        HashFormat.VERSION, 0, 1, List.of(new ExportLink(1, CONTENT_A, CHAIN_A))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("fromSeq");
        assertThatThrownBy(() -> ExportHasher.manifestHash(
                        HashFormat.VERSION, 3, 1, List.of(new ExportLink(1, CONTENT_A, CHAIN_A))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("fromSeq");
    }

    @Test
    @DisplayName("a missing links list is rejected")
    void rejectsNullLinks() {
        assertThatThrownBy(() -> ExportHasher.manifestHash(HashFormat.VERSION, 1, 1, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least one");
    }

    @Test
    @DisplayName("a content hash that is not 32 bytes is rejected")
    void rejectsShortHash() {
        assertThatThrownBy(() -> new ExportLink(1, "aabb", CHAIN_A))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("contentHash");
        assertThatThrownBy(() -> new ExportLink(1, null, CHAIN_A))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("contentHash");
        assertThatThrownBy(() -> new ExportLink(0, CONTENT_A, CHAIN_A))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("seq");
    }

    @Test
    @DisplayName("the first link must be fromSeq")
    void rejectsMismatchedStartingSeq() {
        assertThatThrownBy(() -> ExportHasher.manifestHash(
                        HashFormat.VERSION, 2, 2, List.of(new ExportLink(1, CONTENT_A, CHAIN_A))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("contiguous");
    }

    @Test
    @DisplayName("the link count must match the claimed range")
    void rejectsCountMismatch() {
        assertThatThrownBy(() -> ExportHasher.manifestHash(
                        HashFormat.VERSION, 1, 2, List.of(new ExportLink(1, CONTENT_A, CHAIN_A))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("contiguous");
    }
}

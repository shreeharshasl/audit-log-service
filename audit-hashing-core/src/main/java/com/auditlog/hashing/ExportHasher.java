package com.auditlog.hashing;

import java.util.List;

/**
 * Hash of an export's table of contents. Tag {@link DomainTag#EXPORT_MANIFEST} keeps this digest
 * from being confused with a content or chain hash.
 *
 * <p>The manifest covers sequence numbers and the two stored hashes of each record, not payloads.
 * A later redaction changes neither, so a recipient can regenerate the same manifest from the live
 * store.
 */
public final class ExportHasher {

    private ExportHasher() {}

    public static byte[] manifestHash(int hashVersion, long fromSeq, long toSeq, List<ExportLink> links) {
        if (hashVersion != HashFormat.VERSION) {
            throw new IllegalArgumentException("unsupported hash version " + hashVersion);
        }
        if (fromSeq < 1 || toSeq < fromSeq) {
            throw new IllegalArgumentException("fromSeq must be at least 1 and no greater than toSeq");
        }
        if (links == null || links.isEmpty()) {
            throw new IllegalArgumentException("export must contain at least one record");
        }
        if (links.size() != (toSeq - fromSeq + 1)) {
            throw new IllegalArgumentException("export links must be contiguous from %d to %d, got %d entries"
                    .formatted(fromSeq, toSeq, links.size()));
        }

        HashBuilder builder = HashBuilder.withTag(DomainTag.EXPORT_MANIFEST)
                .int32(hashVersion)
                .int64(fromSeq)
                .int64(toSeq)
                .int32(links.size());
        for (int i = 0; i < links.size(); i++) {
            ExportLink link = links.get(i);
            long expectedSeq = fromSeq + i;
            if (link.seq() != expectedSeq) {
                throw new IllegalArgumentException("export links must be contiguous: expected seq %d but found %d"
                        .formatted(expectedSeq, link.seq()));
            }
            builder.int64(link.seq()).fixed(link.contentHash()).fixed(link.chainHash());
        }
        return builder.build();
    }
}

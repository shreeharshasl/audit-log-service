package com.auditlog.hashing;

import java.util.List;

/** A self-contained slice of the chain a recipient can verify without the live service. */
public record ExportBundle(
        int hashVersion, long fromSeq, long toSeq, String manifestHashHex, List<ExportedRecord> records) {

    public ExportBundle {
        records = List.copyOf(records);
        if (manifestHashHex == null) {
            throw new IllegalArgumentException("manifestHash is required");
        }
    }

    public List<ExportLink> links() {
        return records.stream().map(ExportedRecord::toLink).toList();
    }
}

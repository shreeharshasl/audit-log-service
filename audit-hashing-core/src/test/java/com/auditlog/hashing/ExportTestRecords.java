package com.auditlog.hashing;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import com.fasterxml.jackson.databind.JsonNode;

final class ExportTestRecords {

    private static final UUID EVENT_ID = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    private static final Instant OCCURRED = Instant.parse("2026-01-01T00:00:00Z");
    private static final Instant RECORDED = Instant.parse("2026-01-01T00:00:01Z");

    private ExportTestRecords() {}

    static ExportedRecord record(long seq, String previousChainHashHex, String payloadJson) {
        return record(seq, previousChainHashHex, payloadJson, false);
    }

    static ExportedRecord record(long seq, String previousChainHashHex, String payloadJson, boolean fullyRedacted) {
        JsonNode payload = CanonicalJson.parse(payloadJson);
        CommittedPayload committed = new PayloadCommitter().commit(payload);
        List<FieldCommitment> fields = committed.fields();
        String canonical = CanonicalJson.canonicalString(payload);
        if (fullyRedacted) {
            fields = fields.stream().map(FieldCommitment::redact).toList();
            canonical = "{}";
        }
        AuditEventHeader header =
                new AuditEventHeader(EVENT_ID, "account.updated", "user-1", "account", "acc-1", OCCURRED, RECORDED);
        byte[] contentHash = EventHasher.contentHash(header, Hex.decode(committed.payloadRootHex()));
        byte[] chainHash = EventHasher.chainHash(Hex.decode(previousChainHashHex), contentHash);
        return new ExportedRecord(
                seq,
                header,
                canonical,
                committed.payloadRootHex(),
                Hex.encode(contentHash),
                previousChainHashHex,
                Hex.encode(chainHash),
                HashFormat.VERSION,
                fullyRedacted,
                fields);
    }

    static ExportBundle bundle(ExportedRecord... records) {
        List<ExportedRecord> list = List.of(records);
        long fromSeq = list.get(0).seq();
        long toSeq = list.get(list.size() - 1).seq();
        String manifest = Hex.encode(ExportHasher.manifestHash(
                HashFormat.VERSION,
                fromSeq,
                toSeq,
                list.stream().map(ExportedRecord::toLink).toList()));
        return new ExportBundle(HashFormat.VERSION, fromSeq, toSeq, manifest, list);
    }
}

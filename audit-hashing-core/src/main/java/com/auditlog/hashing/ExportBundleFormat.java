package com.auditlog.hashing;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import com.auditlog.hashing.PayloadLeaf.LeafKind;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * On-the-wire JSON for an export bundle. Kept in the hashing core so the service and the offline
 * verifier emit and parse the same document.
 */
public final class ExportBundleFormat {

    private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

    private ExportBundleFormat() {}

    public static ObjectNode toJson(ExportBundle bundle) {
        ObjectNode root = JSON.objectNode();
        root.put("hashVersion", bundle.hashVersion());
        root.put("fromSeq", bundle.fromSeq());
        root.put("toSeq", bundle.toSeq());
        root.put("manifestHash", bundle.manifestHashHex());
        ArrayNode records = root.putArray("records");
        for (ExportedRecord record : bundle.records()) {
            records.add(recordToJson(record));
        }
        return root;
    }

    public static ExportBundle fromJson(JsonNode root) {
        if (root == null || !root.isObject()) {
            throw new IllegalArgumentException("bundle must be a JSON object");
        }
        int hashVersion = requiredInt(root, "hashVersion");
        long fromSeq = requiredLong(root, "fromSeq");
        long toSeq = requiredLong(root, "toSeq");
        String manifestHash = requiredText(root, "manifestHash");
        JsonNode recordsNode = root.get("records");
        if (recordsNode == null || !recordsNode.isArray()) {
            throw new IllegalArgumentException("records must be a JSON array");
        }
        List<ExportedRecord> records = new ArrayList<>(recordsNode.size());
        for (JsonNode item : recordsNode) {
            records.add(recordFromJson(item));
        }
        return new ExportBundle(hashVersion, fromSeq, toSeq, manifestHash, records);
    }

    private static ObjectNode recordToJson(ExportedRecord record) {
        AuditEventHeader header = record.header();
        ObjectNode node = JSON.objectNode();
        node.put("seq", record.seq());
        node.put("eventId", header.eventId().toString());
        node.put("eventType", header.eventType());
        node.put("actorId", header.actorId());
        node.put("resourceType", header.resourceType());
        node.put("resourceId", header.resourceId());
        node.put("occurredAt", header.occurredAt().toString());
        node.put("occurredAtMicros", EventHasher.toEpochMicros(header.occurredAt()));
        node.put("recordedAt", header.recordedAt().toString());
        node.put("recordedAtMicros", EventHasher.toEpochMicros(header.recordedAt()));
        node.put("canonicalPayload", record.canonicalPayload());
        node.put("payloadRoot", record.payloadRootHex());
        node.put("contentHash", record.contentHashHex());
        node.put("previousChainHash", record.previousChainHashHex());
        node.put("chainHash", record.chainHashHex());
        node.put("hashVersion", record.hashVersion());
        node.put("archived", record.archived());
        ArrayNode commitments = node.putArray("commitments");
        for (FieldCommitment field : record.commitments()) {
            ObjectNode commitment = JSON.objectNode();
            commitment.put("path", field.path());
            commitment.put("kind", field.kind().name());
            if (field.saltHex() == null) {
                commitment.putNull("salt");
            } else {
                commitment.put("salt", field.saltHex());
            }
            commitment.put("commitment", field.commitmentHex());
            commitment.put("redacted", field.redacted());
            commitments.add(commitment);
        }
        return node;
    }

    private static ExportedRecord recordFromJson(JsonNode node) {
        if (node == null || !node.isObject()) {
            throw new IllegalArgumentException("each record must be a JSON object");
        }
        Instant occurredAt = instant(node, "occurredAt", "occurredAtMicros");
        Instant recordedAt = instant(node, "recordedAt", "recordedAtMicros");
        AuditEventHeader header = new AuditEventHeader(
                UUID.fromString(requiredText(node, "eventId")),
                requiredText(node, "eventType"),
                requiredText(node, "actorId"),
                requiredText(node, "resourceType"),
                requiredText(node, "resourceId"),
                occurredAt,
                recordedAt);
        JsonNode commitmentsNode = node.get("commitments");
        if (commitmentsNode == null || !commitmentsNode.isArray()) {
            throw new IllegalArgumentException("commitments must be a JSON array");
        }
        List<FieldCommitment> commitments = new ArrayList<>(commitmentsNode.size());
        for (JsonNode field : commitmentsNode) {
            commitments.add(commitmentFromJson(field));
        }
        return new ExportedRecord(
                requiredLong(node, "seq"),
                header,
                requiredText(node, "canonicalPayload"),
                requiredText(node, "payloadRoot"),
                requiredText(node, "contentHash"),
                requiredText(node, "previousChainHash"),
                requiredText(node, "chainHash"),
                requiredInt(node, "hashVersion"),
                requiredBoolean(node, "archived"),
                commitments);
    }

    private static FieldCommitment commitmentFromJson(JsonNode node) {
        if (node == null || !node.isObject()) {
            throw new IllegalArgumentException("each commitment must be a JSON object");
        }
        JsonNode saltNode = node.get("salt");
        String salt = saltNode == null || saltNode.isNull() ? null : saltNode.asText();
        return new FieldCommitment(
                requiredText(node, "path"),
                LeafKind.valueOf(requiredText(node, "kind")),
                salt,
                requiredText(node, "commitment"),
                requiredBoolean(node, "redacted"));
    }

    private static Instant instant(JsonNode node, String isoField, String microsField) {
        JsonNode micros = node.get(microsField);
        if (micros != null && micros.canConvertToLong()) {
            return EventHasher.fromEpochMicros(micros.longValue());
        }
        return Instant.parse(requiredText(node, isoField));
    }

    private static String requiredText(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull() || !value.isTextual()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.asText();
    }

    private static int requiredInt(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.canConvertToInt()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.intValue();
    }

    private static long requiredLong(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.canConvertToLong()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.longValue();
    }

    private static boolean requiredBoolean(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.isBoolean()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.booleanValue();
    }
}

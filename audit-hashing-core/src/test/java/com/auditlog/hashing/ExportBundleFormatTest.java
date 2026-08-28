package com.auditlog.hashing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

class ExportBundleFormatTest {

    @Test
    @DisplayName("a bundle round-trips through JSON without changing hashes")
    void roundTripsThroughJson() {
        ExportedRecord first = ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":100}");
        ExportedRecord second = ExportTestRecords.record(2, first.chainHashHex(), "{\"amount\":200}");
        ExportBundle original = ExportTestRecords.bundle(first, second);

        ExportBundle parsed = ExportBundleFormat.fromJson(ExportBundleFormat.toJson(original));

        assertThat(parsed.hashVersion()).isEqualTo(original.hashVersion());
        assertThat(parsed.manifestHashHex()).isEqualTo(original.manifestHashHex());
        assertThat(parsed.records()).hasSize(2);
        assertThat(parsed.records().get(0).contentHashHex()).isEqualTo(first.contentHashHex());
        assertThat(parsed.records().get(1).header().occurredAt())
                .isEqualTo(first.header().occurredAt());
        assertThat(new BundleVerifier().verify(parsed).intact()).isTrue();
    }

    @Test
    @DisplayName("redacted salts are encoded as JSON null")
    void redactedSaltIsJsonNull() {
        ExportedRecord archived = ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":100}", true);
        JsonNode json = ExportBundleFormat.toJson(ExportTestRecords.bundle(archived));

        JsonNode salt = json.get("records").get(0).get("commitments").get(0).get("salt");
        assertThat(salt.isNull()).isTrue();
        assertThat(json.get("records").get(0).get("archived").asBoolean()).isTrue();
    }

    @Test
    @DisplayName("ISO timestamps are accepted when micros are absent")
    void parsesIsoTimestampsWithoutMicros() {
        ExportedRecord record = ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"ok\":true}");
        ObjectNode json = ExportBundleFormat.toJson(ExportTestRecords.bundle(record));
        ObjectNode stored = (ObjectNode) json.get("records").get(0);
        stored.remove("occurredAtMicros");
        stored.remove("recordedAtMicros");

        ExportBundle parsed = ExportBundleFormat.fromJson(json);

        assertThat(parsed.records().get(0).header().occurredAt())
                .isEqualTo(record.header().occurredAt());
    }

    @Test
    @DisplayName("a document that is not an object is rejected")
    void rejectsNonObject() {
        assertThatThrownBy(() -> ExportBundleFormat.fromJson(CanonicalJson.parse("[1]")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("JSON object");
        assertThatThrownBy(() -> ExportBundleFormat.fromJson(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("JSON object");
    }

    @Test
    @DisplayName("missing required fields are rejected")
    void rejectsMissingManifest() {
        JsonNode json = ExportBundleFormat.toJson(
                ExportTestRecords.bundle(ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"ok\":true}")));
        ((ObjectNode) json).remove("manifestHash");

        assertThatThrownBy(() -> ExportBundleFormat.fromJson(json))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("manifestHash");
    }

    @Test
    @DisplayName("records must be an array")
    void rejectsMissingRecordsArray() {
        JsonNode json = ExportBundleFormat.toJson(
                ExportTestRecords.bundle(ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"ok\":true}")));
        ((ObjectNode) json).put("records", "nope");

        assertThatThrownBy(() -> ExportBundleFormat.fromJson(json))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("records");
    }

    @Test
    @DisplayName("a missing records field is rejected")
    void rejectsNullRecordsField() {
        JsonNode json = ExportBundleFormat.toJson(
                ExportTestRecords.bundle(ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"ok\":true}")));
        ((ObjectNode) json).remove("records");

        assertThatThrownBy(() -> ExportBundleFormat.fromJson(json))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("records");
    }

    @Test
    @DisplayName("a null record entry is rejected")
    void rejectsNullRecordEntry() {
        ObjectNode json = ExportBundleFormat.toJson(
                ExportTestRecords.bundle(ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"ok\":true}")));
        ((ArrayNode) json.get("records")).set(0, json.nullNode());

        assertThatThrownBy(() -> ExportBundleFormat.fromJson(json))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("each record");
    }

    @Test
    @DisplayName("a null commitment entry is rejected")
    void rejectsNullCommitmentEntry() {
        ObjectNode json = ExportBundleFormat.toJson(
                ExportTestRecords.bundle(ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"ok\":true}")));
        ((ArrayNode) json.get("records").get(0).get("commitments")).set(0, json.nullNode());

        assertThatThrownBy(() -> ExportBundleFormat.fromJson(json))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("each commitment");
    }

    @Test
    @DisplayName("non-textual required strings and non-boolean archived flags are rejected")
    void rejectsWrongJsonTypes() {
        ObjectNode json = ExportBundleFormat.toJson(
                ExportTestRecords.bundle(ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"ok\":true}")));

        ObjectNode eventTypeNumber = json.deepCopy();
        ((ObjectNode) eventTypeNumber.get("records").get(0)).put("eventType", 1);
        assertThatThrownBy(() -> ExportBundleFormat.fromJson(eventTypeNumber))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("eventType");

        ObjectNode archivedString = json.deepCopy();
        ((ObjectNode) archivedString.get("records").get(0)).put("archived", "yes");
        assertThatThrownBy(() -> ExportBundleFormat.fromJson(archivedString))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("archived");

        ObjectNode hashVersionText = json.deepCopy();
        hashVersionText.put("hashVersion", "1");
        assertThatThrownBy(() -> ExportBundleFormat.fromJson(hashVersionText))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("hashVersion");
    }

    @Test
    @DisplayName("a record that is an array, not an object, is rejected")
    void rejectsArrayRecordEntry() {
        ObjectNode json = ExportBundleFormat.toJson(
                ExportTestRecords.bundle(ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"ok\":true}")));
        ArrayNode asArray = json.arrayNode();
        asArray.add(1);
        ((ArrayNode) json.get("records")).set(0, asArray);

        assertThatThrownBy(() -> ExportBundleFormat.fromJson(json))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("each record");
    }

    @Test
    @DisplayName("commitments that are an object rather than an array are rejected")
    void rejectsObjectCommitmentsField() {
        ObjectNode json = ExportBundleFormat.toJson(
                ExportTestRecords.bundle(ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"ok\":true}")));
        ((ObjectNode) json.get("records").get(0)).set("commitments", json.objectNode());

        assertThatThrownBy(() -> ExportBundleFormat.fromJson(json))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("commitments");
    }

    @Test
    @DisplayName("a non-numeric micros field falls back to the ISO timestamp")
    void nonNumericMicrosFallsBackToIso() {
        ExportedRecord record = ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"ok\":true}");
        ObjectNode json = ExportBundleFormat.toJson(ExportTestRecords.bundle(record));
        ((ObjectNode) json.get("records").get(0)).put("occurredAtMicros", "not-a-number");

        ExportBundle parsed = ExportBundleFormat.fromJson(json);

        assertThat(parsed.records().get(0).header().occurredAt())
                .isEqualTo(record.header().occurredAt());
    }

    @Test
    @DisplayName("a seq that cannot convert to a number is rejected")
    void rejectsNonNumericSeq() {
        ObjectNode json = ExportBundleFormat.toJson(
                ExportTestRecords.bundle(ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"ok\":true}")));
        ((ObjectNode) json.get("records").get(0)).put("seq", true);

        assertThatThrownBy(() -> ExportBundleFormat.fromJson(json))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("seq");
    }

    @Test
    @DisplayName("null, non-object records, and missing typed fields are rejected")
    void rejectsMalformedShape() {
        JsonNode honest = ExportBundleFormat.toJson(
                ExportTestRecords.bundle(ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"ok\":true}")));

        ObjectNode noCommitments = honest.deepCopy();
        ((ObjectNode) noCommitments.get("records").get(0)).remove("commitments");
        assertThatThrownBy(() -> ExportBundleFormat.fromJson(noCommitments))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("commitments");

        ObjectNode recordNotObject = honest.deepCopy();
        ((ArrayNode) recordNotObject.get("records")).set(0, recordNotObject.textNode("nope"));
        assertThatThrownBy(() -> ExportBundleFormat.fromJson(recordNotObject))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("each record");

        ObjectNode commitmentNotObject = honest.deepCopy();
        ((ArrayNode) commitmentNotObject.get("records").get(0).get("commitments"))
                .set(0, commitmentNotObject.textNode("nope"));
        assertThatThrownBy(() -> ExportBundleFormat.fromJson(commitmentNotObject))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("each commitment");

        ObjectNode missingArchived = honest.deepCopy();
        ((ObjectNode) missingArchived.get("records").get(0)).remove("archived");
        assertThatThrownBy(() -> ExportBundleFormat.fromJson(missingArchived))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("archived");

        ObjectNode missingSeq = honest.deepCopy();
        ((ObjectNode) missingSeq.get("records").get(0)).remove("seq");
        assertThatThrownBy(() -> ExportBundleFormat.fromJson(missingSeq))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("seq");

        ObjectNode missingVersion = honest.deepCopy();
        missingVersion.remove("hashVersion");
        assertThatThrownBy(() -> ExportBundleFormat.fromJson(missingVersion))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("hashVersion");

        ObjectNode missingEventType = honest.deepCopy();
        ((ObjectNode) missingEventType.get("records").get(0)).putNull("eventType");
        assertThatThrownBy(() -> ExportBundleFormat.fromJson(missingEventType))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("eventType");
    }

    @Test
    @DisplayName("an omitted salt is treated as redacted")
    void omittedSaltIsNull() {
        ExportedRecord redacted = ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"amount\":1}", true);
        ObjectNode json = ExportBundleFormat.toJson(ExportTestRecords.bundle(redacted));
        ((ObjectNode) json.get("records").get(0).get("commitments").get(0)).remove("salt");

        ExportBundle parsed = ExportBundleFormat.fromJson(json);

        assertThat(parsed.records().get(0).commitments().get(0).saltHex()).isNull();
        assertThat(parsed.records().get(0).commitments().get(0).redacted()).isTrue();
    }

    @Test
    @DisplayName("seq, header and payload are required")
    void rejectsMissingRecordFields() {
        ExportedRecord honest = ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"ok\":true}");
        assertThatThrownBy(() -> new ExportedRecord(
                        0,
                        honest.header(),
                        honest.canonicalPayload(),
                        honest.payloadRootHex(),
                        honest.contentHashHex(),
                        honest.previousChainHashHex(),
                        honest.chainHashHex(),
                        honest.hashVersion(),
                        false,
                        honest.commitments()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("seq");
        assertThatThrownBy(() -> new ExportedRecord(
                        1,
                        null,
                        honest.canonicalPayload(),
                        honest.payloadRootHex(),
                        honest.contentHashHex(),
                        honest.previousChainHashHex(),
                        honest.chainHashHex(),
                        honest.hashVersion(),
                        false,
                        honest.commitments()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("header");
        assertThatThrownBy(() -> new ExportedRecord(
                        1,
                        honest.header(),
                        null,
                        honest.payloadRootHex(),
                        honest.contentHashHex(),
                        honest.previousChainHashHex(),
                        honest.chainHashHex(),
                        honest.hashVersion(),
                        false,
                        honest.commitments()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("canonicalPayload");
    }

    @Test
    @DisplayName("a null manifest is rejected")
    void rejectsNullManifest() {
        ExportedRecord record = ExportTestRecords.record(1, HashFormat.GENESIS_CHAIN_HASH, "{\"ok\":true}");
        assertThatThrownBy(() -> new ExportBundle(HashFormat.VERSION, 1, 1, null, List.of(record)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("manifestHash");
    }
}

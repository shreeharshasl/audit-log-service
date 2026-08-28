package com.auditlog.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.auditlog.hashing.BundleVerifier;
import com.auditlog.hashing.ExportBundleFormat;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RetentionRedactionExportIT {

    private static final String CONTEXT = "/audit-service/api";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private Clock clock;

    private final AtomicReference<Instant> now =
            new AtomicReference<>(Instant.parse("2026-06-01T12:00:00Z").truncatedTo(ChronoUnit.MICROS));

    @BeforeEach
    void resetChain() {
        now.set(Instant.parse("2026-06-01T12:00:00Z").truncatedTo(ChronoUnit.MICROS));
        when(clock.instant()).thenAnswer(invocation -> now.get());
        when(clock.getZone()).thenReturn(ZoneOffset.UTC);
        jdbc.execute("TRUNCATE audit_field_commitment, audit_event, audit_export");
        jdbc.update("UPDATE audit_chain_head SET last_seq = 0, last_chain_hash = repeat('0', 64) WHERE id = 1");
        jdbc.update("UPDATE audit_retention_policy SET retain_days = 365 WHERE id = 1");
    }

    @Test
    @DisplayName("redacting a field drops the value and salt but leaves the chain intact")
    void redactionPreservesTheChain() throws Exception {
        append("{\"account\":{\"number\":\"ACC-9911\",\"type\":\"CHECKING\"},\"amount\":250}");

        JsonNode redacted = redact(1, "/account/number");
        assertThat(redacted.get("canonicalPayload").asText())
                .isEqualTo("{\"account\":{\"type\":\"CHECKING\"},\"amount\":250}");
        assertThat(commitment(redacted, "/account/number").get("redacted").asBoolean())
                .isTrue();
        assertThat(commitment(redacted, "/account/number").get("salt").isNull()).isTrue();
        assertThat(commitment(redacted, "/account/type").get("redacted").asBoolean())
                .isFalse();

        JsonNode verify = verifyChain();
        assertThat(verify.get("intact").asBoolean()).isTrue();
        assertThat(fetch(1).get("contentHash").asText())
                .isEqualTo(redacted.get("contentHash").asText());
    }

    @Test
    @DisplayName("redacting every field leaves {} and the chain still verifies")
    void fullyRedactedPayloadIsEmptyObject() throws Exception {
        append("{\"amount\":100,\"currency\":\"USD\"}");

        JsonNode redacted = redact(1, "/amount", "/currency");

        assertThat(redacted.get("canonicalPayload").asText()).isEqualTo("{}");
        assertThat(redacted.get("commitments"))
                .allSatisfy(node -> assertThat(node.get("redacted").asBoolean()).isTrue());
        assertThat(verifyChain().get("intact").asBoolean()).isTrue();
    }

    @Test
    @DisplayName("redaction is itself recorded on the chain")
    void redactionIsRecordedOnTheChain() throws Exception {
        append("{\"amount\":100}");
        redact(1, "/amount");

        JsonNode audit = fetch(2);
        assertThat(audit.get("eventType").asText()).isEqualTo("audit.redaction");
        assertThat(audit.get("actorId").asText()).isEqualTo("bootstrap");
        assertThat(audit.get("resourceType").asText()).isEqualTo("audit_event");
        assertThat(audit.get("resourceId").asText()).isEqualTo("1");
        assertThat(verifyChain().get("intact").asBoolean()).isTrue();
    }

    @Test
    @DisplayName("a path that was never committed is not found")
    void unknownPathIsNotFound() throws Exception {
        append("{\"amount\":100}");

        mockMvc.perform(apiPost("/v1/audit-events/1/redactions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"paths\":[\"/currency\"]}"))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("redacting the same path twice is a conflict")
    void alreadyRedactedIsConflict() throws Exception {
        append("{\"amount\":100}");
        redact(1, "/amount");

        mockMvc.perform(apiPost("/v1/audit-events/1/redactions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"paths\":[\"/amount\"]}"))
                .andExpect(status().isConflict());
    }

    @Test
    @DisplayName("retention archives eligible records in place rather than deleting them")
    void retentionArchivesInPlace() throws Exception {
        append("{\"amount\":100,\"currency\":\"USD\"}");
        now.set(now.get().plus(2, ChronoUnit.DAYS));

        mockMvc.perform(apiPut("/v1/retention/policy")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"retainDays\":1}"))
                .andExpect(status().isOk());

        JsonNode applied = read(mockMvc.perform(apiPost("/v1/retention/apply")).andExpect(status().isOk()));
        assertThat(applied.get("archivedCount").asInt()).isEqualTo(1);

        JsonNode stored = fetch(1);
        assertThat(stored.get("archived").asBoolean()).isTrue();
        assertThat(stored.get("canonicalPayload").asText()).isEqualTo("{}");
        assertThat(stored.get("commitments"))
                .allSatisfy(node -> assertThat(node.get("redacted").asBoolean()).isTrue());
        assertThat(verifyChain().get("intact").asBoolean()).isTrue();

        mockMvc.perform(apiPost("/v1/audit-events/1/redactions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"paths\":[\"/amount\"]}"))
                .andExpect(status().isConflict());
    }

    @Test
    @DisplayName("deleting a row is reported as unauthorized archive, not as a clean chain")
    void deletedRowIsUnauthorizedArchive() throws Exception {
        append("{\"amount\":1}");
        append("{\"amount\":2}");
        append("{\"amount\":3}");
        jdbc.update("DELETE FROM audit_field_commitment WHERE event_seq = 2");
        jdbc.update("DELETE FROM audit_event WHERE seq = 2");

        JsonNode result = verifyChain();

        assertThat(result.get("intact").asBoolean()).isFalse();
        assertThat(violationTypesAt(result, 2)).contains("UNAUTHORIZED_ARCHIVE");
    }

    @Test
    @DisplayName("an export bundle verifies with the hashing core")
    void exportBundleVerifiesOffline() throws Exception {
        append("{\"amount\":100}");
        append("{\"amount\":200}");

        JsonNode exported = read(mockMvc.perform(apiPost("/v1/exports")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fromSeq\":1,\"toSeq\":2}"))
                .andExpect(status().isCreated()));

        assertThat(exported.get("manifestHash").asText()).hasSize(64);
        assertThat(exported.get("records")).hasSize(2);
        assertThat(exported.hasNonNull("exportId")).isTrue();

        BundleVerifier.Result result = new BundleVerifier().verify(ExportBundleFormat.fromJson(exported));
        assertThat(result.intact()).isTrue();

        UUID exportId = UUID.fromString(exported.get("exportId").asText());
        JsonNode regenerated =
                read(mockMvc.perform(apiGet("/v1/exports/{id}", exportId)).andExpect(status().isOk()));
        assertThat(regenerated.get("manifestHash").asText())
                .isEqualTo(exported.get("manifestHash").asText());
    }

    @Test
    @DisplayName("redacting after export does not change the regenerated manifest")
    void redactionDoesNotChangeExportManifest() throws Exception {
        append("{\"amount\":100,\"currency\":\"USD\"}");
        JsonNode exported = read(mockMvc.perform(apiPost("/v1/exports")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fromSeq\":1,\"toSeq\":1}"))
                .andExpect(status().isCreated()));
        redact(1, "/amount");

        JsonNode regenerated = read(mockMvc.perform(
                        apiGet("/v1/exports/{id}", exported.get("exportId").asText()))
                .andExpect(status().isOk()));

        assertThat(regenerated.get("manifestHash").asText())
                .isEqualTo(exported.get("manifestHash").asText());
        assertThat(regenerated.get("records").get(0).get("canonicalPayload").asText())
                .isEqualTo("{\"currency\":\"USD\"}");
        assertThat(new BundleVerifier()
                        .verify(ExportBundleFormat.fromJson(regenerated))
                        .intact())
                .isTrue();
    }

    @Test
    @DisplayName("the compliance report counts redaction, archive, and volume")
    void complianceReportSummarisesTheLog() throws Exception {
        append("{\"amount\":100}");
        mockMvc.perform(appendRequest("user-1", "{\"ok\":true}", null, "session.login", "acc-1"))
                .andExpect(status().isCreated());
        redact(1, "/amount");

        JsonNode report = read(mockMvc.perform(apiGet("/v1/compliance/report")).andExpect(status().isOk()));

        assertThat(report.get("chain").get("intact").asBoolean()).isTrue();
        assertThat(report.get("retention").get("compliant").asBoolean()).isTrue();
        assertThat(report.get("redaction").get("redactedFieldCount").asLong()).isEqualTo(1L);
        assertThat(report.get("redaction").get("eventsWithRedaction").asLong()).isEqualTo(1L);
        assertThat(report.get("volume").get("totalEvents").asLong()).isEqualTo(3L);
        assertThat(report.get("volume").get("byEventType")).hasSize(3);
    }

    @Test
    @DisplayName("retention policy can be read and updated")
    void retentionPolicyRoundTrip() throws Exception {
        JsonNode updated = read(mockMvc.perform(apiPut("/v1/retention/policy")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"retainDays\":30}"))
                .andExpect(status().isOk()));
        assertThat(updated.get("retainDays").asInt()).isEqualTo(30);

        JsonNode fetched = read(mockMvc.perform(apiGet("/v1/retention/policy")).andExpect(status().isOk()));
        assertThat(fetched.get("retainDays").asInt()).isEqualTo(30);
    }

    @Test
    @DisplayName("exporting a range with a missing sequence is rejected")
    void incompleteExportRangeIsConflict() throws Exception {
        append("{\"amount\":1}");
        mockMvc.perform(apiPost("/v1/exports")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fromSeq\":1,\"toSeq\":2}"))
                .andExpect(status().isConflict());
    }

    @Test
    @DisplayName("the service index lists the new privileged endpoints")
    void rootListsNewEndpoints() throws Exception {
        JsonNode json = read(mockMvc.perform(apiGet("/")).andExpect(status().isOk()));
        assertThat(json.get("redactEvent").asText()).contains("/redactions");
        assertThat(json.get("createExport").asText()).contains("/v1/exports");
        assertThat(json.get("complianceReport").asText()).contains("/compliance/report");
    }

    @Test
    @DisplayName("a missing export is not found")
    void missingExportIsNotFound() throws Exception {
        mockMvc.perform(apiGet("/v1/exports/{id}", "11111111-1111-1111-1111-111111111111"))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("redacting a missing sequence is not found")
    void redactMissingSequenceIsNotFound() throws Exception {
        mockMvc.perform(apiPost("/v1/audit-events/99/redactions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"paths\":[\"/amount\"]}"))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("an empty log has a clean compliance report")
    void emptyLogComplianceReportIsClean() throws Exception {
        JsonNode report = read(mockMvc.perform(apiGet("/v1/compliance/report")).andExpect(status().isOk()));

        assertThat(report.get("chain").get("recordsChecked").asInt()).isZero();
        assertThat(report.get("retention").get("compliant").asBoolean()).isTrue();
        assertThat(report.get("volume").get("totalEvents").asLong()).isZero();
    }

    @Test
    @DisplayName("the compliance report includes chain violations when the log is tampered")
    void complianceReportIncludesViolations() throws Exception {
        append("{\"amount\":1}");
        jdbc.update("UPDATE audit_event SET actor_id = ? WHERE seq = ?", "attacker", 1);

        JsonNode report = read(mockMvc.perform(apiGet("/v1/compliance/report")).andExpect(status().isOk()));

        assertThat(report.get("chain").get("intact").asBoolean()).isFalse();
        assertThat(report.get("chain").get("violations")).isNotEmpty();
    }

    @Test
    @DisplayName("applying retention twice does not double-archive")
    void retentionApplyIsIdempotent() throws Exception {
        append("{\"amount\":100}");
        now.set(now.get().plus(2, ChronoUnit.DAYS));
        mockMvc.perform(apiPut("/v1/retention/policy")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"retainDays\":1}"))
                .andExpect(status().isOk());
        mockMvc.perform(apiPost("/v1/retention/apply")).andExpect(status().isOk());

        JsonNode second = read(mockMvc.perform(apiPost("/v1/retention/apply")).andExpect(status().isOk()));
        assertThat(second.get("archivedCount").asInt()).isZero();
    }

    @Test
    @DisplayName("retention skips fields that were already redacted")
    void retentionSkipsAlreadyRedactedFields() throws Exception {
        append("{\"amount\":100,\"currency\":\"USD\"}");
        redact(1, "/amount");
        now.set(now.get().plus(2, ChronoUnit.DAYS));
        mockMvc.perform(apiPut("/v1/retention/policy")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"retainDays\":1}"))
                .andExpect(status().isOk());

        mockMvc.perform(apiPost("/v1/retention/apply")).andExpect(status().isOk());

        JsonNode stored = fetch(1);
        assertThat(stored.get("archived").asBoolean()).isTrue();
        assertThat(stored.get("canonicalPayload").asText()).isEqualTo("{}");
        assertThat(verifyChain().get("intact").asBoolean()).isTrue();
    }

    @Test
    @DisplayName("redacting a parent path covers nested leaves")
    void parentPathRedactsNestedLeaves() throws Exception {
        append("{\"account\":{\"number\":\"ACC-1\",\"type\":\"CHECKING\"},\"amount\":1}");

        JsonNode redacted = redact(1, "/account");

        assertThat(commitment(redacted, "/account/number").get("redacted").asBoolean())
                .isTrue();
        assertThat(commitment(redacted, "/account/type").get("redacted").asBoolean())
                .isTrue();
        assertThat(commitment(redacted, "/amount").get("redacted").asBoolean()).isFalse();
        assertThat(verifyChain().get("intact").asBoolean()).isTrue();
    }

    @Test
    @DisplayName("a parent path still redacts siblings after one child was already redacted")
    void parentPathRedactsRemainingChildren() throws Exception {
        append("{\"account\":{\"number\":\"ACC-1\",\"type\":\"CHECKING\"}}");
        redact(1, "/account/number");

        JsonNode redacted = redact(1, "/account");

        assertThat(commitment(redacted, "/account/number").get("redacted").asBoolean())
                .isTrue();
        assertThat(commitment(redacted, "/account/type").get("redacted").asBoolean())
                .isTrue();
        assertThat(verifyChain().get("intact").asBoolean()).isTrue();
    }

    private JsonNode append(String payloadJson) throws Exception {
        return read(mockMvc.perform(appendRequest("user-1", payloadJson, null)).andExpect(status().isCreated()));
    }

    private JsonNode redact(long seq, String... paths) throws Exception {
        StringBuilder json = new StringBuilder("{\"paths\":[");
        for (int i = 0; i < paths.length; i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(paths[i]).append('"');
        }
        json.append("]}");
        return read(mockMvc.perform(apiPost("/v1/audit-events/" + seq + "/redactions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.toString()))
                .andExpect(status().isOk()));
    }

    private JsonNode fetch(long seq) throws Exception {
        return read(mockMvc.perform(apiGet("/v1/audit-events/{seq}", seq)).andExpect(status().isOk()));
    }

    private JsonNode verifyChain() throws Exception {
        return read(mockMvc.perform(apiGet("/v1/chain/verify")).andExpect(status().isOk()));
    }

    private JsonNode read(org.springframework.test.web.servlet.ResultActions actions) throws Exception {
        return objectMapper.readTree(actions.andReturn().getResponse().getContentAsString());
    }

    private static JsonNode commitment(JsonNode event, String path) {
        for (JsonNode node : event.get("commitments")) {
            if (path.equals(node.get("path").asText())) {
                return node;
            }
        }
        throw new AssertionError("no commitment for " + path);
    }

    private static MockHttpServletRequestBuilder appendRequest(
            String actorId, String payloadJson, String eventId, String eventType, String resourceId) {
        String idField = eventId == null ? "" : "\"eventId\":\"" + eventId + "\",";
        String body =
                """
                {
                  %s"eventType": "%s",
                  "actorId": "%s",
                  "resourceType": "account",
                  "resourceId": "%s",
                  "occurredAt": "2026-01-01T00:00:00Z",
                  "payload": %s
                }
                """
                        .formatted(idField, eventType, actorId, resourceId, payloadJson);
        return apiPost("/v1/audit-events")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body);
    }

    private static MockHttpServletRequestBuilder appendRequest(String actorId, String payloadJson, String eventId) {
        return appendRequest(actorId, payloadJson, eventId, "account.updated", "acc-1");
    }

    private static MockHttpServletRequestBuilder apiGet(String path, Object... uriVars) {
        return TestApiAuth.withKey(get(CONTEXT + path, uriVars).contextPath(CONTEXT));
    }

    private static MockHttpServletRequestBuilder apiPost(String path) {
        return TestApiAuth.withKey(post(CONTEXT + path).contextPath(CONTEXT));
    }

    private static MockHttpServletRequestBuilder apiPut(String path) {
        return TestApiAuth.withKey(put(CONTEXT + path).contextPath(CONTEXT));
    }

    private static List<String> violationTypesAt(JsonNode result, long seq) {
        List<String> types = new ArrayList<>();
        for (JsonNode violation : result.get("violations")) {
            if (violation.get("seq").asLong() == seq) {
                types.add(violation.get("type").asText());
            }
        }
        return types;
    }
}

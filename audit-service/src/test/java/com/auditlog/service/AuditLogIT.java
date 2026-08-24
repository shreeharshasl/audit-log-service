package com.auditlog.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.auditlog.hashing.HashFormat;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * End-to-end coverage of the append path against a real PostgreSQL.
 *
 * <p>The tampering cases mutate the database directly, which is the only honest way to test a
 * tamper-evident store: going through the API can never produce the state we need to detect.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuditLogIT {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void resetChain() {
        jdbc.execute("TRUNCATE audit_field_commitment, audit_event");
        jdbc.update("UPDATE audit_chain_head SET last_seq = 0, last_chain_hash = repeat('0', 64) WHERE id = 1");
    }

    @Test
    @DisplayName("the root path describes how to use the service")
    void rootDescribesTheService() throws Exception {
        String body = mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        JsonNode json = objectMapper.readTree(body);
        assertThat(json.get("service").asText()).isEqualTo("audit-log-service");
        assertThat(json.get("docs").asText()).isEqualTo("/swagger-ui.html");
        assertThat(json.get("health").asText()).isEqualTo("/actuator/health");
    }

    @Test
    @DisplayName("first append starts from the genesis hash and is assigned sequence 1")
    void firstAppendStartsFromGenesis() throws Exception {
        JsonNode appended = append("user-1", "{\"amount\":100,\"currency\":\"USD\"}");

        assertThat(appended.get("seq").asLong()).isEqualTo(1L);
        assertThat(appended.get("hashVersion").asInt()).isEqualTo(HashFormat.VERSION);
        assertThat(fetch(1).get("previousChainHash").asText()).isEqualTo(HashFormat.GENESIS_CHAIN_HASH);
    }

    @Test
    @DisplayName("each append links to its predecessor's chain hash")
    void appendsFormAChain() throws Exception {
        JsonNode first = append("user-1", "{\"amount\":100}");
        JsonNode second = append("user-2", "{\"amount\":200}");
        JsonNode third = append("user-3", "{\"amount\":300}");

        assertThat(second.get("seq").asLong()).isEqualTo(2L);
        assertThat(third.get("seq").asLong()).isEqualTo(3L);
        assertThat(fetch(2).get("previousChainHash").asText())
                .isEqualTo(first.get("chainHash").asText());
        assertThat(fetch(3).get("previousChainHash").asText())
                .isEqualTo(second.get("chainHash").asText());
    }

    @Test
    @DisplayName("an untouched chain verifies as intact")
    void untouchedChainVerifies() throws Exception {
        append("user-1", "{\"amount\":100}");
        append("user-2", "{\"amount\":200}");
        append("user-3", "{\"nested\":{\"tags\":[],\"note\":\"ok\"}}");

        JsonNode result = verifyChain();

        assertThat(result.get("intact").asBoolean()).isTrue();
        assertThat(result.get("recordsChecked").asInt()).isEqualTo(3);
        assertThat(result.get("violations")).isEmpty();
    }

    @Test
    @DisplayName("editing a header field in the database is detected")
    void editedHeaderIsDetected() throws Exception {
        append("user-1", "{\"amount\":100}");
        append("user-2", "{\"amount\":200}");
        append("user-3", "{\"amount\":300}");

        jdbc.update("UPDATE audit_event SET actor_id = ? WHERE seq = ?", "attacker", 2);

        JsonNode result = verifyChain();

        assertThat(result.get("intact").asBoolean()).isFalse();
        assertThat(violationTypesAt(result, 2)).contains("CONTENT_HASH_MISMATCH", "CHAIN_HASH_MISMATCH");
    }

    @Test
    @DisplayName("editing a payload value is caught by its field commitment")
    void editedPayloadIsDetected() throws Exception {
        append("user-1", "{\"amount\":100,\"currency\":\"USD\"}");

        // The header and the payload root are both untouched here, so only the per-field commitment
        // can catch this edit.
        jdbc.update(
                "UPDATE audit_event SET canonical_payload = ? WHERE seq = ?",
                "{\"amount\":999,\"currency\":\"USD\"}",
                1);

        JsonNode result = verifyChain();

        assertThat(result.get("intact").asBoolean()).isFalse();
        assertThat(violationTypesAt(result, 1)).contains("FIELD_COMMITMENT_INVALID");
    }

    @Test
    @DisplayName("reusing an event id is rejected rather than silently ignored")
    void duplicateEventIdIsRejected() throws Exception {
        String eventId = "11111111-1111-1111-1111-111111111111";

        mockMvc.perform(appendRequest("user-1", "{\"amount\":1}", eventId)).andExpect(status().isCreated());
        mockMvc.perform(appendRequest("user-1", "{\"amount\":1}", eventId)).andExpect(status().isConflict());
    }

    @Test
    @DisplayName("a floating point payload value is rejected as a client error")
    void floatPayloadIsRejected() throws Exception {
        mockMvc.perform(appendRequest("user-1", "{\"amount\":10.5}", null)).andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("a payload with duplicate keys is rejected at the HTTP boundary")
    void duplicateKeyPayloadIsRejected() throws Exception {
        mockMvc.perform(appendRequest("user-1", "{\"amount\":1,\"amount\":2}", null))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("a stored record exposes the canonical bytes and every field commitment")
    void storedRecordExposesCommitments() throws Exception {
        append("user-1", "{\"currency\":\"USD\",\"amount\":100}");

        JsonNode stored = fetch(1);

        // Keys come back sorted regardless of the order they were sent in.
        assertThat(stored.get("canonicalPayload").asText()).isEqualTo("{\"amount\":100,\"currency\":\"USD\"}");
        assertThat(stored.get("commitments")).hasSize(2);
        assertThat(stored.get("commitments").get(0).get("path").asText()).isEqualTo("/amount");
        assertThat(stored.get("commitments").get(0).get("salt").asText()).hasSize(64);
        assertThat(stored.get("commitments").get(0).get("redacted").asBoolean()).isFalse();
    }

    @Test
    @DisplayName("missing required fields fail validation before anything is appended")
    void missingFieldsFailValidation() throws Exception {
        mockMvc.perform(post("/api/v1/audit-events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"actorId\":\"user-1\"}"))
                .andExpect(status().isBadRequest());

        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_event", Long.class))
                .isZero();
    }

    private JsonNode append(String actorId, String payloadJson) throws Exception {
        String response = mockMvc.perform(appendRequest(actorId, payloadJson, null))
                .andExpect(status().isCreated())
                .andReturn()
                .getResponse()
                .getContentAsString();
        return objectMapper.readTree(response);
    }

    private JsonNode fetch(long seq) throws Exception {
        String response = mockMvc.perform(get("/api/v1/audit-events/{seq}", seq))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        return objectMapper.readTree(response);
    }

    private JsonNode verifyChain() throws Exception {
        String response = mockMvc.perform(get("/api/v1/chain/verify"))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        return objectMapper.readTree(response);
    }

    private static MockHttpServletRequestBuilder appendRequest(String actorId, String payloadJson, String eventId) {
        String idField = eventId == null ? "" : "\"eventId\":\"" + eventId + "\",";
        String body =
                """
                {
                  %s"eventType": "account.updated",
                  "actorId": "%s",
                  "resourceType": "account",
                  "resourceId": "acc-1",
                  "occurredAt": "2026-01-01T00:00:00Z",
                  "payload": %s
                }
                """
                        .formatted(idField, actorId, payloadJson);
        return post("/api/v1/audit-events")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body);
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

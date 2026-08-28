package com.auditlog.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;

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

import com.auditlog.service.service.ApiKeyHasher;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityIT {

    private static final String CONTEXT = "/audit-service/api";
    private static final String APPEND_ONLY_KEY = "append-only-key-not-for-production";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void resetChainAndClients() {
        jdbc.execute("TRUNCATE audit_field_commitment, audit_event, audit_export");
        jdbc.update("UPDATE audit_chain_head SET last_seq = 0, last_chain_hash = repeat('0', 64) WHERE id = 1");
        jdbc.update("DELETE FROM api_client WHERE name <> 'bootstrap'");
        jdbc.update(
                """
                INSERT INTO api_client (client_id, name, key_hash, roles, enabled, created_at)
                VALUES (?, 'append-only', ?, ARRAY['APPEND']::text[], true, now())
                """,
                UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeee1"),
                ApiKeyHasher.hash(APPEND_ONLY_KEY));
    }

    @Test
    @DisplayName("a missing API key is 401")
    void missingKeyIsUnauthorized() throws Exception {
        String body = mockMvc.perform(get(CONTEXT + "/v1/audit-events").contextPath(CONTEXT))
                .andExpect(status().isUnauthorized())
                .andReturn()
                .getResponse()
                .getContentAsString();
        JsonNode json = objectMapper.readTree(body);
        assertThat(json.get("error").asText()).isEqualTo("unauthorized");
        assertThat(json.get("status").asInt()).isEqualTo(401);
    }

    @Test
    @DisplayName("an unknown API key is 401")
    void unknownKeyIsUnauthorized() throws Exception {
        String body = mockMvc.perform(
                        get(CONTEXT + "/v1/audit-events").contextPath(CONTEXT).header("X-API-Key", "not-a-real-key"))
                .andExpect(status().isUnauthorized())
                .andReturn()
                .getResponse()
                .getContentAsString();
        JsonNode json = objectMapper.readTree(body);
        assertThat(json.get("error").asText()).isEqualTo("unauthorized");
        assertThat(json.get("message").asText()).contains("invalid API key");
    }

    @Test
    @DisplayName("health does not require a key")
    void healthIsPublic() throws Exception {
        mockMvc.perform(get(CONTEXT + "/actuator/health").contextPath(CONTEXT)).andExpect(status().isOk());
    }

    @Test
    @DisplayName("an append-only key can write but cannot redact")
    void appendOnlyKeyCannotRedact() throws Exception {
        mockMvc.perform(
                        keyed(post(CONTEXT + "/v1/audit-events"), APPEND_ONLY_KEY)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                {
                                  "eventType": "account.updated",
                                  "actorId": "user-1",
                                  "resourceType": "account",
                                  "resourceId": "acc-1",
                                  "occurredAt": "2026-01-01T00:00:00Z",
                                  "payload": {"amount": 1}
                                }
                                """))
                .andExpect(status().isCreated());

        String body = mockMvc.perform(keyed(post(CONTEXT + "/v1/audit-events/1/redactions"), APPEND_ONLY_KEY)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"paths\":[\"/amount\"]}"))
                .andExpect(status().isForbidden())
                .andReturn()
                .getResponse()
                .getContentAsString();
        JsonNode json = objectMapper.readTree(body);
        assertThat(json.get("error").asText()).isEqualTo("forbidden");
        assertThat(json.get("status").asInt()).isEqualTo(403);
    }

    @Test
    @DisplayName("Authorization Bearer is accepted as an API key")
    void bearerTokenIsAccepted() throws Exception {
        mockMvc.perform(get(CONTEXT + "/").contextPath(CONTEXT).header("Authorization", "Bearer " + TestApiAuth.KEY))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("a disabled client key is 401")
    void disabledClientIsUnauthorized() throws Exception {
        jdbc.update("UPDATE api_client SET enabled = false WHERE name = 'append-only'");
        mockMvc.perform(
                        keyed(post(CONTEXT + "/v1/audit-events"), APPEND_ONLY_KEY)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                {
                                  "eventType": "account.updated",
                                  "actorId": "user-1",
                                  "resourceType": "account",
                                  "resourceId": "acc-1",
                                  "occurredAt": "2026-01-01T00:00:00Z",
                                  "payload": {"amount": 1}
                                }
                                """))
                .andExpect(status().isUnauthorized());
    }

    private static MockHttpServletRequestBuilder keyed(MockHttpServletRequestBuilder request, String key) {
        return request.contextPath(CONTEXT).header("X-API-Key", key);
    }
}

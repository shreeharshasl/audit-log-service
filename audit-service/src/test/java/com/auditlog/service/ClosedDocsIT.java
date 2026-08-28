package com.auditlog.service;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = "audit.security.open-docs=false")
class ClosedDocsIT {

    private static final String CONTEXT = "/audit-service/api";

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Swagger is not public when open-docs is false")
    void swaggerRequiresAKeyWhenDocsAreClosed() throws Exception {
        mockMvc.perform(get(CONTEXT + "/v3/api-docs").contextPath(CONTEXT)).andExpect(status().isUnauthorized());
    }
}

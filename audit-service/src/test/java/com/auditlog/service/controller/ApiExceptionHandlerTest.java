package com.auditlog.service.controller;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import com.auditlog.service.exception.EventNotFoundException;
import com.auditlog.service.exception.ExportNotFoundException;

class ApiExceptionHandlerTest {

    private final ApiExceptionHandler handler = new ApiExceptionHandler();

    @Test
    @DisplayName("a missing event is 404")
    void missingEventIsNotFound() {
        var response = handler.onNotFound(new EventNotFoundException(9));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(response.getBody().error()).isEqualTo("not_found");
        assertThat(response.getBody().message()).contains("sequence 9");
    }

    @Test
    @DisplayName("a missing export is 404")
    void missingExportIsNotFound() {
        UUID id = UUID.fromString("11111111-1111-1111-1111-111111111111");
        var response = handler.onMissingExport(new ExportNotFoundException(id));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(response.getBody().message()).contains(id.toString());
    }

    @Test
    @DisplayName("an unknown URL is 404")
    void unknownUrlIsNotFound() {
        var response = handler.onMissingResource(new NoResourceFoundException(HttpMethod.GET, "/v1/nope"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(response.getBody().message()).contains("/v1/nope");
    }

    @Test
    @DisplayName("an unreadable body without a cause uses the outer message")
    void unreadableBodyWithoutCauseUsesOuterMessage() {
        var response = handler.onUnreadableBody(new HttpMessageNotReadableException("broken json"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().error()).isEqualTo("malformed_request");
        assertThat(response.getBody().message()).contains("broken json");
    }

    @Test
    @DisplayName("an unreadable body whose cause has no message still answers")
    void unreadableBodyWithSilentCauseUsesOuterMessage() {
        var response = handler.onUnreadableBody(
                new HttpMessageNotReadableException("broken json", new RuntimeException(), null));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().message()).isEqualTo("broken json");
    }
}

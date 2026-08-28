package com.auditlog.service.controller;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import com.auditlog.service.dto.ApiErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;

final class JsonAuthErrorWriter {

    private JsonAuthErrorWriter() {}

    static void write(
            HttpServletResponse response, ObjectMapper mapper, HttpStatus status, String error, String message)
            throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        mapper.writeValue(response.getOutputStream(), ApiErrorResponse.of(status.value(), error, message));
    }
}

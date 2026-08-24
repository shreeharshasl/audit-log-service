package com.auditlog.service.dto;

import java.time.Instant;
import java.util.List;

public record ApiErrorResponse(Instant timestamp, int status, String error, String message, List<String> details) {

    public ApiErrorResponse {
        details = List.copyOf(details);
    }

    public static ApiErrorResponse of(int status, String error, String message) {
        return new ApiErrorResponse(Instant.now(), status, error, message, List.of());
    }

    public static ApiErrorResponse of(int status, String error, String message, List<String> details) {
        return new ApiErrorResponse(Instant.now(), status, error, message, List.copyOf(details));
    }
}

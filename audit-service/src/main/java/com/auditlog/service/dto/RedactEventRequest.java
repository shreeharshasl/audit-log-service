package com.auditlog.service.dto;

import java.util.List;

import jakarta.validation.constraints.NotEmpty;

public record RedactEventRequest(@NotEmpty List<String> paths) {

    public RedactEventRequest {
        paths = paths == null ? List.of() : List.copyOf(paths);
    }
}

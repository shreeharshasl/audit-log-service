package com.auditlog.service.dto;

import java.time.Instant;
import java.util.UUID;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * @param eventId optional; supplying one makes a retry detectable as a duplicate rather than
 *     appending the same event twice
 * @param occurredAt when the event happened in the caller's world; untrusted, and never used for
 *     ordering
 */
public record AppendEventRequest(
        UUID eventId,
        @NotNull @Size(min = 1, max = 200) String eventType,
        @NotNull @Size(min = 1, max = 200) String actorId,
        @NotNull @Size(min = 1, max = 200) String resourceType,
        @NotNull @Size(min = 1, max = 200) String resourceId,
        @NotNull Instant occurredAt,
        @NotNull JsonNode payload) {}

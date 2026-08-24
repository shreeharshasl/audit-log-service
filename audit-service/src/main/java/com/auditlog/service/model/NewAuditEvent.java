package com.auditlog.service.model;

import java.time.Instant;
import java.util.UUID;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * An append request as the service layer sees it, already detached from HTTP.
 *
 * <p>{@code recordedAt} is absent by design: it is assigned by the service when the record is
 * accepted, never supplied by the caller.
 */
public record NewAuditEvent(
        UUID eventId,
        String eventType,
        String actorId,
        String resourceType,
        String resourceId,
        Instant occurredAt,
        JsonNode payload) {}

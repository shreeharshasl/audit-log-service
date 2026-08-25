package com.auditlog.service.model;

/**
 * Keyset page request. {@code beforeSeq} is an exclusive cursor: the next page is records whose
 * {@code seq} is strictly less than this value, because listing is newest-first.
 *
 * @param requestedPageSize caller-supplied size, still unclamped; the service applies the configured
 *     floor and ceiling
 */
public record AuditEventQuery(
        Long beforeSeq,
        String actorId,
        String eventType,
        String resourceType,
        String resourceId,
        Integer requestedPageSize) {}

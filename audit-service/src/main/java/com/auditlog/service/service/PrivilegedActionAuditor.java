package com.auditlog.service.service;

import java.time.Clock;
import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.auditlog.service.model.NewAuditEvent;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Writes a chain record for operator actions that change stored data or copy it out. The append
 * joins the caller's transaction, so a failed audit write rolls the privileged action back.
 */
@Service
public class PrivilegedActionAuditor {

    static final String REDACTION = "audit.redaction";
    static final String RETENTION_POLICY = "audit.retention.policy";
    static final String RETENTION_APPLY = "audit.retention.apply";
    static final String EXPORT_CREATE = "audit.export.create";
    static final String EXPORT_READ = "audit.export.read";

    private final AuditEventService events;
    private final Clock clock;

    public PrivilegedActionAuditor(AuditEventService events, Clock clock) {
        this.events = events;
        this.clock = clock;
    }

    public void redacted(String actorId, long seq, List<String> paths) {
        ObjectNode payload = JsonNodeFactory.instance.objectNode();
        payload.put("seq", seq);
        ArrayNode pathNode = payload.putArray("paths");
        for (String path : paths) {
            pathNode.add(path);
        }
        events.append(new NewAuditEvent(
                null, REDACTION, actorId, "audit_event", Long.toString(seq), clock.instant(), payload));
    }

    public void policyUpdated(String actorId, int retainDays) {
        ObjectNode payload = JsonNodeFactory.instance.objectNode();
        payload.put("retainDays", retainDays);
        events.append(new NewAuditEvent(
                null, RETENTION_POLICY, actorId, "retention_policy", "default", clock.instant(), payload));
    }

    public void retentionApplied(String actorId, int archivedCount, int retainDays) {
        ObjectNode payload = JsonNodeFactory.instance.objectNode();
        payload.put("archivedCount", archivedCount);
        payload.put("retainDays", retainDays);
        events.append(new NewAuditEvent(
                null, RETENTION_APPLY, actorId, "retention_policy", "default", clock.instant(), payload));
    }

    public void exportCreated(String actorId, UUID exportId, long fromSeq, long toSeq) {
        ObjectNode payload = exportPayload(exportId, fromSeq, toSeq);
        events.append(new NewAuditEvent(
                null, EXPORT_CREATE, actorId, "audit_export", exportId.toString(), clock.instant(), payload));
    }

    public void exportRead(String actorId, UUID exportId, long fromSeq, long toSeq) {
        ObjectNode payload = exportPayload(exportId, fromSeq, toSeq);
        events.append(new NewAuditEvent(
                null, EXPORT_READ, actorId, "audit_export", exportId.toString(), clock.instant(), payload));
    }

    private static ObjectNode exportPayload(UUID exportId, long fromSeq, long toSeq) {
        ObjectNode payload = JsonNodeFactory.instance.objectNode();
        payload.put("exportId", exportId.toString());
        payload.put("fromSeq", fromSeq);
        payload.put("toSeq", toSeq);
        return payload;
    }
}

package com.auditlog.service.controller;

import java.net.URI;

import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auditlog.service.dto.AppendEventRequest;
import com.auditlog.service.dto.AppendEventResponse;
import com.auditlog.service.dto.AuditEventResponse;
import com.auditlog.service.model.AuditRecord;
import com.auditlog.service.model.NewAuditEvent;
import com.auditlog.service.service.AuditEventService;

@RestController
@RequestMapping("/api/v1/audit-events")
public class AuditEventController {

    private final AuditEventService service;

    public AuditEventController(AuditEventService service) {
        this.service = service;
    }

    @PostMapping
    public ResponseEntity<AppendEventResponse> append(@Valid @RequestBody AppendEventRequest request) {
        AuditRecord record = service.append(new NewAuditEvent(
                request.eventId(),
                request.eventType(),
                request.actorId(),
                request.resourceType(),
                request.resourceId(),
                request.occurredAt(),
                request.payload()));
        return ResponseEntity.created(URI.create("/api/v1/audit-events/" + record.seq()))
                .body(AppendEventResponse.from(record));
    }

    @GetMapping("/{seq}")
    public AuditEventResponse findBySeq(@PathVariable("seq") long seq) {
        AuditRecord record = service.findBySeq(seq);
        return AuditEventResponse.from(record, service.findCommitments(seq));
    }
}

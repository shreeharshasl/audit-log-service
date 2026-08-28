package com.auditlog.service.controller;

import jakarta.validation.Valid;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auditlog.service.dto.AuditEventResponse;
import com.auditlog.service.dto.RedactEventRequest;
import com.auditlog.service.model.AuditRecord;
import com.auditlog.service.service.AuditEventService;
import com.auditlog.service.service.RedactionService;

@RestController
@RequestMapping("/v1/audit-events")
public class RedactionController {

    private final RedactionService redactionService;
    private final AuditEventService eventService;

    public RedactionController(RedactionService redactionService, AuditEventService eventService) {
        this.redactionService = redactionService;
        this.eventService = eventService;
    }

    @PostMapping("/{seq}/redactions")
    @PreAuthorize("hasRole('REDACT')")
    public AuditEventResponse redact(@PathVariable("seq") long seq, @Valid @RequestBody RedactEventRequest request) {
        AuditRecord record = redactionService.redact(seq, request.paths(), CurrentApiClient.name());
        return AuditEventResponse.from(record, eventService.findCommitments(seq));
    }
}

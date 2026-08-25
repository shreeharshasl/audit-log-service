package com.auditlog.service.dto;

/** What a browser hitting the context root needs in order to find the real endpoints. */
public record ServiceInfoResponse(
        String service,
        String health,
        String docs,
        String appendEvents,
        String getEvent,
        String listEvents,
        String verifyChain,
        String redactEvent,
        String retentionPolicy,
        String createExport,
        String complianceReport) {}

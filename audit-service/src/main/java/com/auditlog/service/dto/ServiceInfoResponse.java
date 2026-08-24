package com.auditlog.service.dto;

/** What a browser hitting {@code /} needs in order to find the real endpoints. */
public record ServiceInfoResponse(
        String service, String health, String docs, String appendEvents, String getEvent, String verifyChain) {}

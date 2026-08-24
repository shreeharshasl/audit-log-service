package com.auditlog.service.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.auditlog.service.dto.ChainVerificationResponse;
import com.auditlog.service.service.AuditEventService;
import com.auditlog.service.service.ChainVerificationService;

@RestController
@RequestMapping("/v1/chain")
public class ChainController {

    private final ChainVerificationService verificationService;
    private final AuditEventService eventService;

    public ChainController(ChainVerificationService verificationService, AuditEventService eventService) {
        this.verificationService = verificationService;
        this.eventService = eventService;
    }

    /** Verifies a range of the chain, defaulting to the whole of it. */
    @GetMapping("/verify")
    public ChainVerificationResponse verify(
            @RequestParam(name = "fromSeq", defaultValue = "1") long fromSeq,
            @RequestParam(name = "toSeq", required = false) Long toSeq) {
        long upperBound = toSeq != null ? toSeq : Math.max(eventService.latestSeq(), fromSeq);
        return ChainVerificationResponse.from(verificationService.verify(fromSeq, upperBound));
    }
}

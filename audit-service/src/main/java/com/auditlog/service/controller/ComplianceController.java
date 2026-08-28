package com.auditlog.service.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auditlog.service.dto.ComplianceReportResponse;
import com.auditlog.service.service.ComplianceService;

@RestController
@RequestMapping("/v1/compliance")
public class ComplianceController {

    private final ComplianceService complianceService;

    public ComplianceController(ComplianceService complianceService) {
        this.complianceService = complianceService;
    }

    @GetMapping("/report")
    @PreAuthorize("hasRole('COMPLIANCE')")
    public ComplianceReportResponse report() {
        return ComplianceReportResponse.from(complianceService.report());
    }
}

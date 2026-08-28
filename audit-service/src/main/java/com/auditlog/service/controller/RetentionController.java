package com.auditlog.service.controller;

import jakarta.validation.Valid;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auditlog.service.dto.RetentionApplyResponse;
import com.auditlog.service.dto.RetentionPolicyResponse;
import com.auditlog.service.dto.UpdateRetentionPolicyRequest;
import com.auditlog.service.service.RetentionService;

@RestController
@RequestMapping("/v1/retention")
public class RetentionController {

    private final RetentionService retentionService;

    public RetentionController(RetentionService retentionService) {
        this.retentionService = retentionService;
    }

    @GetMapping("/policy")
    @PreAuthorize("hasRole('RETAIN')")
    public RetentionPolicyResponse policy() {
        return RetentionPolicyResponse.from(retentionService.policy());
    }

    @PutMapping("/policy")
    @PreAuthorize("hasRole('RETAIN')")
    public RetentionPolicyResponse updatePolicy(@Valid @RequestBody UpdateRetentionPolicyRequest request) {
        return RetentionPolicyResponse.from(
                retentionService.updatePolicy(request.retainDays(), CurrentApiClient.name()));
    }

    @PostMapping("/apply")
    @PreAuthorize("hasRole('RETAIN')")
    public RetentionApplyResponse apply() {
        return RetentionApplyResponse.from(retentionService.apply(CurrentApiClient.name()));
    }
}

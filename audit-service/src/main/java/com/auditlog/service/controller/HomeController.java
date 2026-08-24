package com.auditlog.service.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auditlog.service.dto.ServiceInfoResponse;

@RestController
public class HomeController {

    @GetMapping("/")
    public ServiceInfoResponse home() {
        return new ServiceInfoResponse(
                "audit-log-service",
                "/actuator/health",
                "/swagger-ui.html",
                "POST /api/v1/audit-events",
                "GET /api/v1/audit-events/{seq}",
                "GET /api/v1/chain/verify");
    }
}

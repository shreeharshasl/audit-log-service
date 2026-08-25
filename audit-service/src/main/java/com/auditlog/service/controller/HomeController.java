package com.auditlog.service.controller;

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auditlog.service.dto.ServiceInfoResponse;

@RestController
public class HomeController {

    private final ServiceInfoResponse info;

    public HomeController(ServerProperties serverProperties) {
        String root = serverProperties.getServlet().getContextPath();
        this.info = new ServiceInfoResponse(
                "audit-log-service",
                root + "/actuator/health",
                root + "/swagger-ui.html",
                "POST " + root + "/v1/audit-events",
                "GET " + root + "/v1/audit-events/{seq}",
                "GET " + root + "/v1/audit-events?beforeSeq=&limit=",
                "GET " + root + "/v1/chain/verify",
                "POST " + root + "/v1/audit-events/{seq}/redactions",
                "GET|PUT " + root + "/v1/retention/policy",
                "POST " + root + "/v1/exports",
                "GET " + root + "/v1/compliance/report");
    }

    @GetMapping("/")
    public ServiceInfoResponse home() {
        return info;
    }
}

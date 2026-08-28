package com.auditlog.service.config;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import com.auditlog.service.service.ApiClientService;

/** Seeds or refreshes the bootstrap API client after Flyway has created {@code api_client}. */
@Component
public class ApiClientBootstrap implements ApplicationRunner {

    private final ApiClientService clients;

    public ApiClientBootstrap(ApiClientService clients) {
        this.clients = clients;
    }

    @Override
    public void run(ApplicationArguments args) {
        clients.ensureBootstrapClient();
    }
}

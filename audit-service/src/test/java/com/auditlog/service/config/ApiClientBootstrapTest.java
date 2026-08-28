package com.auditlog.service.config;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.DefaultApplicationArguments;

import com.auditlog.service.service.ApiClientService;

class ApiClientBootstrapTest {

    @Test
    @DisplayName("startup seeds the bootstrap API client")
    void startupSeedsBootstrapClient() {
        ApiClientService clients = mock(ApiClientService.class);
        new ApiClientBootstrap(clients).run(new DefaultApplicationArguments());
        verify(clients).ensureBootstrapClient();
    }
}

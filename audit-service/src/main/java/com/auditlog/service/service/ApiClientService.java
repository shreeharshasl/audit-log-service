package com.auditlog.service.service;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.auditlog.service.config.AuditProperties;
import com.auditlog.service.model.ApiClient;
import com.auditlog.service.model.ApiRole;
import com.auditlog.service.repository.ApiClientRepository;

/** Looks up API clients by hashed key and seeds the bootstrap client on startup. */
@Service
public class ApiClientService {

    static final String BOOTSTRAP_CLIENT_NAME = "bootstrap";

    private final ApiClientRepository clients;
    private final AuditProperties properties;
    private final Clock clock;

    public ApiClientService(ApiClientRepository clients, AuditProperties properties, Clock clock) {
        this.clients = clients;
        this.properties = properties;
        this.clock = clock;
    }

    public Optional<ApiClient> authenticate(String key) {
        if (key == null || key.isBlank()) {
            return Optional.empty();
        }
        return clients.findEnabledByKeyHash(ApiKeyHasher.hash(key));
    }

    public void ensureBootstrapClient() {
        String key = properties.security().bootstrapKey();
        if (key.isBlank()) {
            return;
        }
        String hash = ApiKeyHasher.hash(key);
        Set<ApiRole> allRoles = EnumSet.allOf(ApiRole.class);
        Optional<ApiClient> existing = clients.findByName(BOOTSTRAP_CLIENT_NAME);
        if (existing.isEmpty()) {
            clients.insert(new ApiClient(
                    UUID.randomUUID(),
                    BOOTSTRAP_CLIENT_NAME,
                    hash,
                    allRoles,
                    true,
                    clock.instant().truncatedTo(ChronoUnit.MICROS)));
            return;
        }
        ApiClient client = existing.get();
        if (!hash.equals(client.keyHashHex()) || !client.roles().equals(allRoles) || !client.enabled()) {
            clients.updateCredentials(client.clientId(), hash, allRoles);
        }
    }
}

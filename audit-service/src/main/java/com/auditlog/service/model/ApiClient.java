package com.auditlog.service.model;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/** An API caller identified by a hashed key and a set of roles. */
public record ApiClient(
        UUID clientId, String name, String keyHashHex, Set<ApiRole> roles, boolean enabled, Instant createdAt) {

    public ApiClient {
        roles = Set.copyOf(roles);
    }
}

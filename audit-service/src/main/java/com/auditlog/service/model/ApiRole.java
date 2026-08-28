package com.auditlog.service.model;

/** Capability granted to an API client. Values are stored as the enum name. */
public enum ApiRole {
    APPEND,
    READ,
    VERIFY,
    REDACT,
    RETAIN,
    EXPORT,
    COMPLIANCE;

    public String authority() {
        return "ROLE_" + name();
    }

    public static ApiRole fromStored(String value) {
        try {
            return valueOf(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("unknown API role stored on a client: " + value, e);
        }
    }
}

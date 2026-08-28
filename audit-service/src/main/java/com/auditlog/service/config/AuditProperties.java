package com.auditlog.service.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import com.auditlog.hashing.PayloadLimits;

/** Externalized limits and security settings, bound from the {@code audit.*} tree. */
@ConfigurationProperties(prefix = "audit")
public record AuditProperties(Payload payload, Query query, Security security) {

    public AuditProperties {
        if (security == null) {
            security = new Security("", true);
        }
    }

    public record Payload(int maxDepth, int maxLeaves, int maxCanonicalBytes, int maxStringLength) {
        public PayloadLimits toLimits() {
            return new PayloadLimits(maxDepth, maxLeaves, maxCanonicalBytes, maxStringLength);
        }
    }

    public record Query(int defaultPageSize, int maxPageSize) {

        /** Clamps a caller-supplied page size instead of trusting or rejecting it. */
        public int resolvePageSize(Integer requested) {
            if (requested == null || requested < 1) {
                return defaultPageSize;
            }
            return Math.min(requested, maxPageSize);
        }
    }

    /**
     * {@code bootstrapKey} is hashed on startup and stored as the {@code bootstrap} client. Blank
     * means no client is seeded, so every authenticated path returns 401 until one is inserted.
     */
    public record Security(String bootstrapKey, boolean openDocs) {

        public Security {
            bootstrapKey = bootstrapKey == null ? "" : bootstrapKey;
        }
    }
}

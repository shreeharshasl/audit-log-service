package com.auditlog.service.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import com.auditlog.hashing.PayloadLimits;

/** Externalized limits for the append and query paths, bound from the {@code audit.*} tree. */
@ConfigurationProperties(prefix = "audit")
public record AuditProperties(Payload payload, Query query) {

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
}

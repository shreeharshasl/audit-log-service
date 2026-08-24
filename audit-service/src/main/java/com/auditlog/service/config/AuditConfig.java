package com.auditlog.service.config;

import java.time.Clock;

import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.auditlog.hashing.PayloadCommitter;
import com.fasterxml.jackson.core.JsonParser;

@Configuration
@EnableConfigurationProperties(AuditProperties.class)
public class AuditConfig {

    @Bean
    public PayloadCommitter payloadCommitter(AuditProperties properties) {
        return new PayloadCommitter(properties.payload().toLimits());
    }

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    /**
     * Rejects duplicate JSON object keys at the HTTP boundary.
     *
     * <p>{@link com.auditlog.hashing.CanonicalJson} refuses duplicate keys, but by the time a request
     * body reaches it the payload has already been parsed by Spring's mapper. Without this, Spring
     * would silently apply last-wins and hand the core a payload the caller never sent, so the
     * commitment would cover different bytes than the request contained.
     */
    @Bean
    public Jackson2ObjectMapperBuilderCustomizer strictDuplicateDetection() {
        return builder -> builder.featuresToEnable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    }
}

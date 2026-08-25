package com.auditlog.service.model;

import java.time.Instant;

/** The single-row retention window. */
public record RetentionPolicy(int retainDays, Instant updatedAt) {}

package com.auditlog.service.model;

import java.time.Instant;

/** How many events a retention run archived. */
public record RetentionApplication(int archivedCount, int retainDays, Instant cutoff) {}

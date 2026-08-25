package com.auditlog.service.model;

import java.time.Instant;
import java.util.UUID;

import com.auditlog.hashing.ExportBundle;

/** An export that was recorded and can be regenerated from the live store. */
public record GeneratedExport(UUID exportId, Instant createdAt, ExportBundle bundle) {}

package com.auditlog.service.model;

import java.time.Instant;
import java.util.UUID;

public record ExportMetadata(
        UUID exportId, long fromSeq, long toSeq, int recordCount, String manifestHashHex, Instant createdAt) {}

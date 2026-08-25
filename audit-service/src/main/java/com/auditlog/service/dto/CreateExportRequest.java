package com.auditlog.service.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

public record CreateExportRequest(@NotNull @Min(1) Long fromSeq, @NotNull @Min(1) Long toSeq) {}

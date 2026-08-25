package com.auditlog.service.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

public record UpdateRetentionPolicyRequest(@NotNull @Min(1) @Max(36500) Integer retainDays) {}

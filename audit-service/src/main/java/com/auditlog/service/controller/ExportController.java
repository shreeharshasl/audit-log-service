package com.auditlog.service.controller;

import java.net.URI;
import java.util.UUID;

import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.auditlog.hashing.ExportBundleFormat;
import com.auditlog.service.dto.CreateExportRequest;
import com.auditlog.service.model.GeneratedExport;
import com.auditlog.service.service.ExportService;
import com.fasterxml.jackson.databind.node.ObjectNode;

@RestController
@RequestMapping("/v1/exports")
public class ExportController {

    private final ExportService exportService;

    public ExportController(ExportService exportService) {
        this.exportService = exportService;
    }

    @PostMapping
    @PreAuthorize("hasRole('EXPORT')")
    public ResponseEntity<ObjectNode> create(@Valid @RequestBody CreateExportRequest request) {
        GeneratedExport generated = exportService.create(request.fromSeq(), request.toSeq(), CurrentApiClient.name());
        URI location = ServletUriComponentsBuilder.fromCurrentContextPath()
                .path("/v1/exports/{id}")
                .buildAndExpand(generated.exportId())
                .toUri();
        return ResponseEntity.created(location).body(toJson(generated));
    }

    @GetMapping("/{exportId}")
    @PreAuthorize("hasRole('EXPORT')")
    public ObjectNode regenerate(@PathVariable("exportId") UUID exportId) {
        return toJson(exportService.regenerate(exportId, CurrentApiClient.name()));
    }

    private static ObjectNode toJson(GeneratedExport generated) {
        ObjectNode body = ExportBundleFormat.toJson(generated.bundle());
        body.put("exportId", generated.exportId().toString());
        body.put("createdAt", generated.createdAt().toString());
        return body;
    }
}

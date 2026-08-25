package com.auditlog.service.exception;

import java.util.UUID;

public class ExportNotFoundException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public ExportNotFoundException(UUID exportId) {
        super("no export " + exportId);
    }
}

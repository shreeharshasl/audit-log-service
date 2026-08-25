package com.auditlog.service.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import com.auditlog.hashing.CanonicalJsonException;
import com.auditlog.service.dto.ApiErrorResponse;
import com.auditlog.service.exception.DuplicateEventException;
import com.auditlog.service.exception.EventConflictException;
import com.auditlog.service.exception.EventNotFoundException;
import com.auditlog.service.exception.ExportNotFoundException;
import com.auditlog.service.exception.FieldPathNotFoundException;

@RestControllerAdvice
public class ApiExceptionHandler {

    /**
     * A payload this service cannot canonicalize is a client error, not a server fault: floats,
     * out-of-range integers, oversized payloads and duplicate keys all land here.
     */
    @ExceptionHandler(CanonicalJsonException.class)
    public ResponseEntity<ApiErrorResponse> onCanonicalJson(CanonicalJsonException e) {
        return build(HttpStatus.BAD_REQUEST, "invalid_payload", e.getMessage());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiErrorResponse> onIllegalArgument(IllegalArgumentException e) {
        return build(HttpStatus.BAD_REQUEST, "invalid_request", e.getMessage());
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiErrorResponse> onUnreadableBody(HttpMessageNotReadableException e) {
        return build(HttpStatus.BAD_REQUEST, "malformed_request", rootMessage(e));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiErrorResponse> onValidationFailure(MethodArgumentNotValidException e) {
        List<String> details = e.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + " " + error.getDefaultMessage())
                .sorted()
                .toList();
        return ResponseEntity.badRequest()
                .body(ApiErrorResponse.of(
                        HttpStatus.BAD_REQUEST.value(), "validation_failed", "request is not valid", details));
    }

    @ExceptionHandler(DuplicateEventException.class)
    public ResponseEntity<ApiErrorResponse> onDuplicate(DuplicateEventException e) {
        return build(HttpStatus.CONFLICT, "duplicate_event", e.getMessage());
    }

    @ExceptionHandler(EventNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> onNotFound(EventNotFoundException e) {
        return build(HttpStatus.NOT_FOUND, "not_found", e.getMessage());
    }

    @ExceptionHandler(FieldPathNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> onMissingPath(FieldPathNotFoundException e) {
        return build(HttpStatus.NOT_FOUND, "not_found", e.getMessage());
    }

    @ExceptionHandler(ExportNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> onMissingExport(ExportNotFoundException e) {
        return build(HttpStatus.NOT_FOUND, "not_found", e.getMessage());
    }

    @ExceptionHandler(EventConflictException.class)
    public ResponseEntity<ApiErrorResponse> onConflict(EventConflictException e) {
        return build(HttpStatus.CONFLICT, e.error(), e.getMessage());
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ApiErrorResponse> onMissingResource(NoResourceFoundException e) {
        return build(HttpStatus.NOT_FOUND, "not_found", "no resource at " + e.getResourcePath());
    }

    private static ResponseEntity<ApiErrorResponse> build(HttpStatus status, String error, String message) {
        return ResponseEntity.status(status).body(ApiErrorResponse.of(status.value(), error, message));
    }

    /** Jackson wraps the useful detail, including duplicate key reports, in the cause. */
    private static String rootMessage(Throwable e) {
        Throwable cause = e.getCause();
        return cause != null && cause.getMessage() != null ? cause.getMessage() : String.valueOf(e.getMessage());
    }
}

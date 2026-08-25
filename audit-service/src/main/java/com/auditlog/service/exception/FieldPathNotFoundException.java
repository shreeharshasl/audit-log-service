package com.auditlog.service.exception;

/** A JSON Pointer that does not match any stored field commitment. */
public class FieldPathNotFoundException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public FieldPathNotFoundException(long seq, String path) {
        super("no field at path " + path + " on sequence " + seq);
    }
}

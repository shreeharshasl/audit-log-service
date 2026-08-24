package com.auditlog.service.exception;

public class EventNotFoundException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public EventNotFoundException(long seq) {
        super("no audit event at sequence " + seq);
    }
}

package com.auditlog.service.service;

import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.auditlog.service.config.AuditProperties;
import com.auditlog.service.model.AuditEventPage;
import com.auditlog.service.model.AuditEventQuery;
import com.auditlog.service.model.AuditRecord;
import com.auditlog.service.repository.AuditEventRepository;

/**
 * Keyset listing of the log. A new class rather than another method on {@link AuditEventService}:
 * append and query change for different reasons.
 */
@Service
public class AuditEventQueryService {

    private final AuditEventRepository events;
    private final AuditProperties properties;

    public AuditEventQueryService(AuditEventRepository events, AuditProperties properties) {
        this.events = events;
        this.properties = properties;
    }

    @Transactional(readOnly = true)
    public AuditEventPage list(AuditEventQuery query) {
        validate(query);
        AuditEventQuery filters = normalize(query);
        int pageSize = properties.query().resolvePageSize(query.requestedPageSize());
        List<AuditRecord> fetched = events.findPage(filters, pageSize + 1);
        boolean hasMore = fetched.size() > pageSize;
        List<AuditRecord> items = hasMore ? List.copyOf(fetched.subList(0, pageSize)) : fetched;
        Long nextBeforeSeq = hasMore ? items.getLast().seq() : null;
        return new AuditEventPage(items, hasMore, nextBeforeSeq);
    }

    private static void validate(AuditEventQuery query) {
        if (query.beforeSeq() != null && query.beforeSeq() < 1) {
            throw new IllegalArgumentException("beforeSeq must be at least 1");
        }
        if (notBlank(query.resourceId()) && !notBlank(query.resourceType())) {
            throw new IllegalArgumentException("resourceId requires resourceType");
        }
    }

    private static AuditEventQuery normalize(AuditEventQuery query) {
        return new AuditEventQuery(
                query.beforeSeq(),
                blankToNull(query.actorId()),
                blankToNull(query.eventType()),
                blankToNull(query.resourceType()),
                blankToNull(query.resourceId()),
                query.requestedPageSize());
    }

    private static String blankToNull(String value) {
        return notBlank(value) ? value : null;
    }

    private static boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }
}

package com.auditlog.service.model;

import java.util.List;

/**
 * One page of records in seq-descending order.
 *
 * @param nextBeforeSeq the cursor to pass as {@code beforeSeq} for the following page; null when
 *     {@code hasMore} is false
 */
public record AuditEventPage(List<AuditRecord> items, boolean hasMore, Long nextBeforeSeq) {

    public AuditEventPage {
        items = List.copyOf(items);
    }
}

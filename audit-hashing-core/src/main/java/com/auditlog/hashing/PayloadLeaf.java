package com.auditlog.hashing;

/**
 * One committable position in a payload.
 *
 * <p>Empty objects and empty arrays are leaves in their own right. If they were skipped, the
 * difference between {@code {"tags":[]}} and {@code {}} would not be covered by any commitment, and
 * an empty container could be silently added or removed after the fact.
 *
 * @param path RFC 6901 JSON Pointer, for example {@code /account/number} or {@code /tags/0}
 * @param kind coarse type, carried for API responses and redaction reporting
 * @param canonicalValue canonical JSON text of the value; self-describing, so the string "123" and
 *     the integer 123 commit to different bytes
 */
public record PayloadLeaf(String path, LeafKind kind, String canonicalValue) {

    public enum LeafKind {
        STRING,
        INTEGER,
        BOOLEAN,
        NULL,
        EMPTY_OBJECT,
        EMPTY_ARRAY
    }
}

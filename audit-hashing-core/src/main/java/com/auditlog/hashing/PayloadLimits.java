package com.auditlog.hashing;

/**
 * Bounds on payload shape.
 *
 * <p>Per-field commitments make the cost of accepting a payload proportional to its leaf count, so
 * an unbounded payload is a cheap way to make the append path do unbounded work while holding the
 * chain lock. These limits are enforced before any hashing happens.
 *
 * @param maxDepth maximum object/array nesting depth
 * @param maxLeaves maximum number of committable positions
 * @param maxCanonicalBytes maximum size of the canonical payload encoding
 * @param maxStringLength maximum length of any single string value
 */
public record PayloadLimits(int maxDepth, int maxLeaves, int maxCanonicalBytes, int maxStringLength) {

    public static final PayloadLimits DEFAULT = new PayloadLimits(8, 256, 64 * 1024, 8 * 1024);

    public PayloadLimits {
        if (maxDepth < 1 || maxLeaves < 1 || maxCanonicalBytes < 1 || maxStringLength < 1) {
            throw new IllegalArgumentException("payload limits must all be positive");
        }
    }
}

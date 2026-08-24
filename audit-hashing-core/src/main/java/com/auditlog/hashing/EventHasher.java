package com.auditlog.hashing;

import java.security.MessageDigest;
import java.time.Instant;

/**
 * The two hashes stored on every record.
 *
 * <p>{@code contentHash} covers the record itself. {@code chainHash} covers the content hash and the
 * previous record's chain hash, so each link transitively commits to the entire history before it:
 * altering record 10 changes the chain hash of record 10 and of every record after it.
 */
public final class EventHasher {

    private EventHasher() {}

    /** Hash of the record's own content, independent of its position in the chain. */
    public static byte[] contentHash(AuditEventHeader header, byte[] payloadRoot) {
        return HashBuilder.withTag(DomainTag.CONTENT)
                .int32(HashFormat.VERSION)
                .field(header.eventId().toString())
                .field(header.eventType())
                .field(header.actorId())
                .field(header.resourceType())
                .field(header.resourceId())
                .int64(toEpochMicros(header.occurredAt()))
                .int64(toEpochMicros(header.recordedAt()))
                .fixed(payloadRoot)
                .build();
    }

    /** Link hash binding this record to its predecessor. */
    public static byte[] chainHash(byte[] previousChainHash, byte[] contentHash) {
        if (previousChainHash.length != 32 || contentHash.length != 32) {
            throw new IllegalArgumentException("chain inputs must be 32-byte SHA-256 digests");
        }
        return HashBuilder.withTag(DomainTag.CHAIN)
                .int32(HashFormat.VERSION)
                .fixed(previousChainHash)
                .fixed(contentHash)
                .build();
    }

    public static boolean matches(byte[] expected, byte[] actual) {
        return MessageDigest.isEqual(expected, actual);
    }

    /**
     * Timestamps enter the hash as epoch microseconds rather than formatted text.
     *
     * <p>Text formatting is a canonicalization trap: {@code Instant.toString()} drops trailing zeros,
     * so the same instant can render two different ways and produce two different hashes. Microsecond
     * precision matches what PostgreSQL {@code timestamptz} actually stores, so nothing is lost in the
     * round trip that would later fail verification.
     */
    static long toEpochMicros(Instant instant) {
        return Math.multiplyExact(instant.getEpochSecond(), 1_000_000L) + instant.getNano() / 1_000L;
    }
}

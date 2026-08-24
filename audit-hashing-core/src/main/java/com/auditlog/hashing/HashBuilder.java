package com.auditlog.hashing;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Builds a SHA-256 digest over an unambiguously framed byte stream.
 *
 * <p>Every variable-length component is written with a 4-byte big-endian length prefix. This is not
 * decoration: concatenating raw fields lets distinct inputs collide trivially, because ("ab", "c")
 * and ("a", "bc") produce identical bytes. Framing removes that whole class of forgery, and it is
 * the single easiest thing to get wrong in a hash chain.
 */
public final class HashBuilder {

    private final MessageDigest digest;

    private HashBuilder(byte domainTag) {
        this.digest = newDigest();
        this.digest.update(domainTag);
    }

    public static HashBuilder withTag(byte domainTag) {
        return new HashBuilder(domainTag);
    }

    public static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by the Java platform spec", e);
        }
    }

    /** Writes a length-prefixed UTF-8 string. Null is distinct from the empty string. */
    public HashBuilder field(String value) {
        if (value == null) {
            digest.update(intToBytes(-1));
            return this;
        }
        return field(value.getBytes(StandardCharsets.UTF_8));
    }

    /** Writes length-prefixed bytes. Null is distinct from a zero-length array. */
    public HashBuilder field(byte[] value) {
        if (value == null) {
            digest.update(intToBytes(-1));
            return this;
        }
        digest.update(intToBytes(value.length));
        digest.update(value);
        return this;
    }

    /**
     * Writes bytes with no length prefix. Only valid for values whose width is fixed by the format,
     * such as a 32-byte hash in a position where exactly one hash is expected.
     */
    public HashBuilder fixed(byte[] value) {
        digest.update(value);
        return this;
    }

    public HashBuilder int32(int value) {
        digest.update(intToBytes(value));
        return this;
    }

    public HashBuilder int64(long value) {
        digest.update(ByteBuffer.allocate(Long.BYTES).putLong(value).array());
        return this;
    }

    public byte[] build() {
        return digest.digest();
    }

    private static byte[] intToBytes(int value) {
        return ByteBuffer.allocate(Integer.BYTES).putInt(value).array();
    }
}

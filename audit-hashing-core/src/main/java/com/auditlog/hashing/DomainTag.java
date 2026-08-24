package com.auditlog.hashing;

/**
 * First byte fed into every digest, so that a hash computed for one purpose can never be mistaken
 * for a hash computed for another. Without this an attacker could try to make a payload field
 * commitment double as a valid content hash.
 *
 * <p>Values are frozen. Adding a new kind of hash means adding a new tag, never reusing one.
 */
public final class DomainTag {

    public static final byte CONTENT = 0x01;
    public static final byte FIELD_COMMITMENT = 0x02;
    public static final byte PAYLOAD_ROOT = 0x03;
    public static final byte CHAIN = 0x04;
    public static final byte CHECKPOINT = 0x05;
    public static final byte EXPORT_MANIFEST = 0x06;

    private DomainTag() {}
}

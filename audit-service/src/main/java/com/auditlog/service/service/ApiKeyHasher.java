package com.auditlog.service.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import com.auditlog.hashing.HashBuilder;
import com.auditlog.hashing.Hex;

/**
 * Hashes an API key for lookup. Keys are high-entropy random strings, so a single SHA-256 is
 * enough; a password KDF would only slow honest lookups.
 */
public final class ApiKeyHasher {

    private ApiKeyHasher() {}

    public static String hash(String key) {
        MessageDigest digest = HashBuilder.newDigest();
        return Hex.encode(digest.digest(key.getBytes(StandardCharsets.UTF_8)));
    }
}

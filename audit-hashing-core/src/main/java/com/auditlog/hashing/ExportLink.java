package com.auditlog.hashing;

/**
 * The hashes an export manifest commits to for one record. Values and salts are deliberately
 * omitted: redaction after an export must not change the manifest, and a recipient checking
 * integrity of the chain does not need the plaintext.
 */
public record ExportLink(long seq, String contentHashHex, String chainHashHex) {

    public ExportLink {
        if (seq < 1) {
            throw new IllegalArgumentException("seq must be at least 1");
        }
        requireSha256Hex(contentHashHex, "contentHash");
        requireSha256Hex(chainHashHex, "chainHash");
    }

    public byte[] contentHash() {
        return Hex.decode(contentHashHex);
    }

    public byte[] chainHash() {
        return Hex.decode(chainHashHex);
    }

    private static void requireSha256Hex(String value, String name) {
        if (value == null || value.length() != 64) {
            throw new IllegalArgumentException(name + " must be 64 lowercase hex characters");
        }
        Hex.decode(value);
    }
}

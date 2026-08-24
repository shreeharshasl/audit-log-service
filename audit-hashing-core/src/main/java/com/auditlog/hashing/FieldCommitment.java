package com.auditlog.hashing;

import com.auditlog.hashing.PayloadLeaf.LeafKind;

/**
 * A binding commitment to the value at one payload position.
 *
 * <p>The salt is what makes redaction meaningful. A commitment to an unsalted account number is
 * recoverable by brute force in seconds, so redaction that kept the value's hash would not actually
 * remove the data. Dropping a 256-bit random salt alongside the value leaves the commitment
 * verifiable in place but the value unrecoverable.
 *
 * <p>Hashes and salts are held as hex rather than {@code byte[]} so instances are genuinely
 * immutable and safe to hand out, and because this is the form they take in the API and in export
 * bundles.
 *
 * @param saltHex null once the field has been redacted
 */
public record FieldCommitment(String path, LeafKind kind, String saltHex, String commitmentHex, boolean redacted) {

    public FieldCommitment {
        if (path == null) {
            throw new IllegalArgumentException("path is required");
        }
        if (commitmentHex == null) {
            throw new IllegalArgumentException("commitment is required for " + path);
        }
        if (redacted && saltHex != null) {
            throw new IllegalArgumentException(
                    "redacted field " + path + " still carries its salt, which would leave the value recoverable");
        }
        if (!redacted && saltHex == null) {
            throw new IllegalArgumentException("non-redacted field " + path + " is missing its salt");
        }
    }

    public byte[] commitmentBytes() {
        return Hex.decode(commitmentHex);
    }

    public byte[] saltBytes() {
        return saltHex == null ? null : Hex.decode(saltHex);
    }

    /** The same commitment with the salt discarded, which is exactly what redaction does. */
    public FieldCommitment redact() {
        return new FieldCommitment(path, kind, null, commitmentHex, true);
    }
}

package com.auditlog.hashing;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Produces and checks the per-field commitments that let a single field be redacted later without
 * invalidating the record's hash or anything downstream of it in the chain.
 *
 * <p>The alternative, hashing the payload as one opaque blob, is simpler but forces a chain rewrite
 * the first time a privacy request arrives.
 */
public final class PayloadCommitter {

    public static final int SALT_LENGTH = 32;

    private final PayloadFlattener flattener;
    private final SecureRandom random;

    public PayloadCommitter(PayloadFlattener flattener, SecureRandom random) {
        this.flattener = flattener;
        this.random = random;
    }

    public PayloadCommitter() {
        this(new PayloadFlattener(), new SecureRandom());
    }

    /** Commits every position in the payload under a fresh random salt. */
    public CommittedPayload commit(JsonNode payload) {
        List<PayloadLeaf> leaves = flattener.flatten(payload);
        List<FieldCommitment> commitments = new ArrayList<>(leaves.size());
        for (PayloadLeaf leaf : leaves) {
            byte[] salt = new byte[SALT_LENGTH];
            random.nextBytes(salt);
            byte[] commitment = commitmentOf(leaf.path(), salt, leaf.canonicalValue());
            commitments.add(
                    new FieldCommitment(leaf.path(), leaf.kind(), Hex.encode(salt), Hex.encode(commitment), false));
        }
        return new CommittedPayload(commitments, Hex.encode(payloadRoot(commitments)));
    }

    /**
     * Recomputes the commitment for a single position.
     *
     * @param canonicalValue the leaf's canonical JSON text, as produced by {@link PayloadFlattener}
     */
    public static byte[] commitmentOf(String path, byte[] salt, String canonicalValue) {
        return HashBuilder.withTag(DomainTag.FIELD_COMMITMENT)
                .int32(HashFormat.VERSION)
                .field(path)
                .field(salt)
                .field(canonicalValue)
                .build();
    }

    /**
     * Hashes the full set of commitments into the single value the content hash covers.
     *
     * <p>Committing the count as well as the entries is what stops a field from being appended or
     * dropped without detection.
     */
    public static byte[] payloadRoot(List<FieldCommitment> commitments) {
        List<FieldCommitment> ordered = new ArrayList<>(commitments);
        ordered.sort(Comparator.comparing(FieldCommitment::path));

        HashBuilder builder = HashBuilder.withTag(DomainTag.PAYLOAD_ROOT)
                .int32(HashFormat.VERSION)
                .int32(ordered.size());
        String previousPath = null;
        for (FieldCommitment field : ordered) {
            if (field.path().equals(previousPath)) {
                throw new CanonicalJsonException("duplicate commitment for path " + field.path());
            }
            previousPath = field.path();
            builder.field(field.path()).fixed(field.commitmentBytes());
        }
        return builder.build();
    }

    /**
     * Checks stored commitments against the payload as it exists now.
     *
     * <p>Redacted fields are reported as unverifiable rather than valid or invalid: once the salt is
     * gone the commitment cannot be independently reproduced, which is a real and documented limit of
     * this scheme.
     */
    public List<CommitmentCheck> verify(JsonNode payload, List<FieldCommitment> stored) {
        // A fully redacted payload is stored as {}. The flattener would otherwise treat that
        // empty root as an uncommitted EMPTY_OBJECT leaf, which is the shape redaction produces
        // rather than a field that was added after the fact.
        boolean fullyRedactedEmpty = payload != null
                && payload.isObject()
                && payload.isEmpty()
                && !stored.isEmpty()
                && stored.stream().allMatch(FieldCommitment::redacted);
        if (fullyRedactedEmpty) {
            return stored.stream()
                    .map(field -> new CommitmentCheck(field.path(), CommitmentCheck.Status.UNVERIFIABLE_REDACTED))
                    .toList();
        }

        List<PayloadLeaf> leaves = flattener.flatten(payload);
        List<CommitmentCheck> results = new ArrayList<>();

        for (FieldCommitment field : stored) {
            if (field.redacted()) {
                results.add(new CommitmentCheck(field.path(), CommitmentCheck.Status.UNVERIFIABLE_REDACTED));
                continue;
            }
            PayloadLeaf leaf = leaves.stream()
                    .filter(l -> l.path().equals(field.path()))
                    .findFirst()
                    .orElse(null);
            if (leaf == null) {
                results.add(new CommitmentCheck(field.path(), CommitmentCheck.Status.MISSING_FROM_PAYLOAD));
                continue;
            }
            byte[] recomputed = commitmentOf(field.path(), field.saltBytes(), leaf.canonicalValue());
            boolean matches = java.security.MessageDigest.isEqual(recomputed, field.commitmentBytes());
            results.add(new CommitmentCheck(
                    field.path(), matches ? CommitmentCheck.Status.VALID : CommitmentCheck.Status.VALUE_ALTERED));
        }

        for (PayloadLeaf leaf : leaves) {
            boolean known = stored.stream().anyMatch(f -> f.path().equals(leaf.path()));
            if (known) {
                continue;
            }
            if (isRedactionResidue(leaf, stored)) {
                continue;
            }
            results.add(new CommitmentCheck(leaf.path(), CommitmentCheck.Status.UNCOMMITTED_FIELD));
        }
        return results;
    }

    /**
     * Empty containers (and null array slots) left behind after a child was redacted are not new
     * fields. The flattener would otherwise report them as uncommitted leaves.
     */
    private static boolean isRedactionResidue(PayloadLeaf leaf, List<FieldCommitment> stored) {
        if (leaf.kind() != PayloadLeaf.LeafKind.EMPTY_OBJECT
                && leaf.kind() != PayloadLeaf.LeafKind.EMPTY_ARRAY
                && leaf.kind() != PayloadLeaf.LeafKind.NULL) {
            return false;
        }
        String prefix = leaf.path();
        List<FieldCommitment> under = stored.stream()
                .filter(field -> prefix.isEmpty() || field.path().startsWith(prefix + "/"))
                .toList();
        return !under.isEmpty() && under.stream().allMatch(FieldCommitment::redacted);
    }

    /** Outcome of checking one position. */
    public record CommitmentCheck(String path, Status status) {
        public enum Status {
            VALID,
            VALUE_ALTERED,
            MISSING_FROM_PAYLOAD,
            UNCOMMITTED_FIELD,
            UNVERIFIABLE_REDACTED
        }

        public boolean isViolation() {
            return status == Status.VALUE_ALTERED
                    || status == Status.MISSING_FROM_PAYLOAD
                    || status == Status.UNCOMMITTED_FIELD;
        }
    }
}

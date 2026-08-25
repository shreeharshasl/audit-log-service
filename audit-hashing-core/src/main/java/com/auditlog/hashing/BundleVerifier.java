package com.auditlog.hashing;

import java.util.ArrayList;
import java.util.List;

/**
 * Recomputes every hash in an export bundle the same way the service recomputes the live chain.
 *
 * <p>Nothing here trusts a stored digest. A recipient who only has the JSON file can still tell
 * whether the records in it are internally consistent.
 */
public final class BundleVerifier {

    private final PayloadCommitter committer;

    public BundleVerifier() {
        this(new PayloadCommitter());
    }

    public BundleVerifier(PayloadCommitter committer) {
        this.committer = committer;
    }

    public Result verify(ExportBundle bundle) {
        List<Check> checks = new ArrayList<>();
        if (bundle.hashVersion() != HashFormat.VERSION) {
            checks.add(new Check(
                    0,
                    Check.Type.HASH_VERSION_MISMATCH,
                    "bundle hash version %d is not %d".formatted(bundle.hashVersion(), HashFormat.VERSION)));
        }

        List<ExportedRecord> records = bundle.records();
        String previousChainHash = null;
        long expectedSeq = bundle.fromSeq();
        for (ExportedRecord record : records) {
            if (record.seq() != expectedSeq) {
                checks.add(new Check(
                        expectedSeq,
                        Check.Type.UNAUTHORIZED_ARCHIVE,
                        "expected sequence %d but found %d; records cannot be deleted, only archived in place"
                                .formatted(expectedSeq, record.seq())));
            }
            expectedSeq = record.seq() + 1;
            if (record.hashVersion() != HashFormat.VERSION) {
                checks.add(new Check(
                        record.seq(),
                        Check.Type.HASH_VERSION_MISMATCH,
                        "record hash version %d is not %d".formatted(record.hashVersion(), HashFormat.VERSION)));
            }
            byte[] recomputedContent = verifyContentHash(record, checks);
            verifyChainHash(record, recomputedContent, checks);
            verifyLink(record, previousChainHash, checks);
            verifyPayload(record, checks);
            previousChainHash = record.chainHashHex();
        }
        while (expectedSeq <= bundle.toSeq()) {
            checks.add(new Check(
                    expectedSeq,
                    Check.Type.UNAUTHORIZED_ARCHIVE,
                    "sequence %d is missing; records cannot be deleted, only archived in place"
                            .formatted(expectedSeq)));
            expectedSeq++;
        }

        verifyManifest(bundle, checks);
        return new Result(
                bundle.fromSeq(), bundle.toSeq(), records.size(), bundle.manifestHashHex(), List.copyOf(checks));
    }

    private static byte[] verifyContentHash(ExportedRecord record, List<Check> checks) {
        byte[] recomputed = EventHasher.contentHash(record.header(), Hex.decode(record.payloadRootHex()));
        if (!Hex.encode(recomputed).equals(record.contentHashHex())) {
            checks.add(new Check(
                    record.seq(),
                    Check.Type.CONTENT_HASH_MISMATCH,
                    "stored content hash %s but the record's fields hash to %s"
                            .formatted(record.contentHashHex(), Hex.encode(recomputed))));
        }
        return recomputed;
    }

    private static void verifyChainHash(ExportedRecord record, byte[] contentHash, List<Check> checks) {
        byte[] recomputed = EventHasher.chainHash(Hex.decode(record.previousChainHashHex()), contentHash);
        if (!Hex.encode(recomputed).equals(record.chainHashHex())) {
            checks.add(new Check(
                    record.seq(),
                    Check.Type.CHAIN_HASH_MISMATCH,
                    "stored chain hash %s but the link recomputes to %s"
                            .formatted(record.chainHashHex(), Hex.encode(recomputed))));
        }
    }

    private static void verifyLink(ExportedRecord record, String previousChainHash, List<Check> checks) {
        String expected = previousChainHash;
        if (expected == null) {
            if (record.seq() != 1) {
                return;
            }
            expected = HashFormat.GENESIS_CHAIN_HASH;
        }
        if (!record.previousChainHashHex().equals(expected)) {
            checks.add(new Check(
                    record.seq(),
                    Check.Type.BROKEN_LINK,
                    "record claims predecessor %s but the preceding chain hash is %s"
                            .formatted(record.previousChainHashHex(), expected)));
        }
    }

    private void verifyPayload(ExportedRecord record, List<Check> checks) {
        String recomputedRoot = Hex.encode(PayloadCommitter.payloadRoot(record.commitments()));
        if (!recomputedRoot.equals(record.payloadRootHex())) {
            checks.add(new Check(
                    record.seq(),
                    Check.Type.PAYLOAD_ROOT_MISMATCH,
                    "stored commitments hash to %s but the record's payload root is %s"
                            .formatted(recomputedRoot, record.payloadRootHex())));
            return;
        }
        try {
            committer.verify(CanonicalJson.parse(record.canonicalPayload()), record.commitments()).stream()
                    .filter(PayloadCommitter.CommitmentCheck::isViolation)
                    .forEach(check -> checks.add(new Check(
                            record.seq(),
                            Check.Type.FIELD_COMMITMENT_INVALID,
                            "%s at %s".formatted(check.status(), check.path()))));
        } catch (CanonicalJsonException e) {
            checks.add(new Check(
                    record.seq(),
                    Check.Type.FIELD_COMMITMENT_INVALID,
                    "stored payload is no longer canonical JSON: " + e.getMessage()));
        }
    }

    private static void verifyManifest(ExportBundle bundle, List<Check> checks) {
        try {
            String recomputed = Hex.encode(
                    ExportHasher.manifestHash(bundle.hashVersion(), bundle.fromSeq(), bundle.toSeq(), bundle.links()));
            if (!recomputed.equals(bundle.manifestHashHex())) {
                checks.add(new Check(
                        0,
                        Check.Type.MANIFEST_MISMATCH,
                        "claimed manifest %s but the records hash to %s"
                                .formatted(bundle.manifestHashHex(), recomputed)));
            }
        } catch (RuntimeException e) {
            checks.add(new Check(0, Check.Type.MANIFEST_MISMATCH, e.getMessage()));
        }
    }

    public record Result(long fromSeq, long toSeq, int recordsChecked, String manifestHashHex, List<Check> checks) {

        public Result {
            checks = List.copyOf(checks);
        }

        public boolean intact() {
            return checks.isEmpty();
        }
    }

    public record Check(long seq, Type type, String detail) {

        public enum Type {
            CONTENT_HASH_MISMATCH,
            CHAIN_HASH_MISMATCH,
            BROKEN_LINK,
            UNAUTHORIZED_ARCHIVE,
            PAYLOAD_ROOT_MISMATCH,
            FIELD_COMMITMENT_INVALID,
            MANIFEST_MISMATCH,
            HASH_VERSION_MISMATCH
        }
    }
}

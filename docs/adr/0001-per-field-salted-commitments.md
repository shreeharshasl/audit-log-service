# ADR 0001: Commit to payloads per field, with salts, from the first record

Status: accepted
Date: 2026-08-24

## Context

Scenario A requires a hash chain over event records. Scenario B, which arrives later, requires that
individual sensitive fields inside a payload be redactable without breaking that chain.

The obvious Scenario A implementation hashes the payload as one opaque blob. It is less code and it
satisfies the literal Scenario A requirement.

## Decision

Hash payloads as a set of per-field salted commitments from the very first record, even though
Scenario A alone does not require it.

Each leaf position in the payload gets:

```
commitment = H(0x02, version, fieldPath, salt, canonicalValue)
```

with a fresh 256-bit random salt, and the record commits to:

```
payloadRoot = H(0x03, version, count, [(fieldPath, commitment)] sorted by path)
```

## Consequences

Redaction becomes: delete the value, delete the salt, keep the commitment. `payloadRoot` is
unchanged, so `contentHash` is unchanged, so every `chainHash` downstream is unchanged. No
migration, no chain rewrite, no second hash format to maintain.

The salt is not optional. Committing to an unsalted account number leaves it recoverable by brute
force over a small keyspace, which would make "redaction" cosmetic rather than real.

Committing the field count as well as the entries is what prevents a field being added or dropped
without detection. Committing the path inside each commitment is what prevents two values being
swapped between positions.

### Costs accepted

- More code and more storage than a single payload hash: one row per payload field.
- The append path does work proportional to the payload's leaf count, which is why
  `PayloadLimits` bounds depth, leaf count, and size before any hashing happens.
- The scheme looks more elaborate than Scenario A justifies on its own, and needs this document to
  explain why.

### Alternative rejected

Introduce the commitment scheme in Scenario B, behind a hash format version. Rejected because it
means writing and forever maintaining a dual-format verifier, and because the migration would have
to either rewrite history or leave the chain permanently split across two schemes. The work is the
same size; doing it first avoids the migration entirely.

### Alternative rejected

Redact by appending a tombstone event and filtering the value at read time, leaving the original
record untouched. Rejected because the sensitive value remains in the datastore and in backups,
which does not satisfy a privacy requirement — it only hides the value from well-behaved readers.

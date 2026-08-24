# ADR 0002: Canonical JSON accepts only integers in the safe range

Status: accepted
Date: 2026-08-24

## Context

Hashing a payload requires a byte-exact serialization. If the same logical payload can serialize two
ways, verification fails at random and the failure looks like tampering.

RFC 8785 (JSON Canonicalization Scheme) is the standard answer. Its hardest requirement is number
formatting: numbers must be serialized exactly as ECMAScript's `Number::toString` would, which means
reproducing shortest-round-trip double formatting and its exponent thresholds. Java's
`Double.toString` does not match it (`1.0E21` versus `1e+21`, `1.0` versus `1`).

## Decision

Implement canonicalization ourselves, matching RFC 8785 for object key ordering (UTF-16 code unit,
which is `String::compareTo`) and string escaping, but **reject non-integer numbers and integers
outside ±(2^53 − 1)**.

## Consequences

The accepted input is a strict subset of RFC 8785, and for everything in that subset our output is
byte-identical to a compliant JCS implementation. We get interoperability where it matters without
owning a floating-point formatting routine whose bugs would only surface months later as an
unexplained chain break.

The `2^53 − 1` bound is not arbitrary: beyond it IEEE-754 doubles lose integer precision, so a
JavaScript client reading the record back would silently see a different number than we hashed.
Rejecting the value is better than committing to one a consumer cannot reproduce.

Callers needing decimals send them as strings (`"10.50"`) or as integer minor units (`1050`). For
audit payloads this is a better practice regardless of hashing.

### Costs accepted

- The API rejects payloads that plain JSON would accept, which must be documented clearly and
  produce an error message that names the offending path and says what to do instead.
- We cannot claim unqualified RFC 8785 compliance.

### Also decided here

- Duplicate object keys are rejected rather than resolved last-wins, because two parsers can
  disagree about which value wins and therefore about the hash.
- Timestamps are hashed as epoch microseconds, not as formatted text. `Instant.toString()` drops
  trailing zeros, so the same instant can render two ways. Microseconds match PostgreSQL
  `timestamptz` precision exactly, so the round trip through storage loses nothing.
- Every variable-length value fed into a digest carries a 4-byte length prefix. Without framing,
  `("ab","c")` and `("a","bc")` hash identically.

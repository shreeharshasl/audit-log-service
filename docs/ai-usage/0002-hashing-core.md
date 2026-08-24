# 0002 — Hashing core

Date: 2026-08-24
Disposition: **Edited** (accepted after two defects were found in review)

## Intent

Implement canonical JSON serialization, per-field salted payload commitments, and the content/chain
hash construction, as an isolated module with no persistence dependency.

## Constraints

- No Spring, no JDBC, no JPA. The offline verifier must depend on this module alone, so that a
  bundle recipient runs the same bytes the service ran.
- Deterministic: identical logical input must always produce identical bytes.
- Bounded work per payload, since the append path holds a lock while hashing.

## Acceptance criteria

- Golden vectors freeze the byte format so an accidental change fails the build.
- Tampering with any single field is detected and localized to its exact path.
- Redaction leaves the payload root unchanged.
- Coverage floor of 90% lines / 85% branches. Achieved: 97.0% instructions, 97.3% branches, 74 tests.

## Defects found in review

**1. A test that passed for the wrong reason.** `contentHashCoversPayload` asserted that hashing the
same header twice produced different results, and concluded the payload was covered. It passed only
because salts are random — it would have kept passing if the payload root had been dropped from the
content hash entirely. Rewritten to hash two explicitly different payload roots and compare.

This is the failure mode that matters most in a test suite for tamper evidence: a green test that
verifies nothing is worse than a missing one, because it stops anyone from looking again.

**2. Coverage floor met by lowering the bar.** Branch coverage came in at 82% against an 85% floor.
The tempting fix is to lower the threshold. Instead the uncovered branches were identified from the
JaCoCo report and tested — they were almost entirely input-validation rejection paths, which is
precisely the code that must work when hostile input arrives. `ValidationEdgeCaseTest` covers them.

## Design points that came out of review

- **Length framing.** Every variable-length value written into a digest carries a 4-byte length
  prefix. Without it, `("ab","c")` and `("a","bc")` produce identical bytes.
- **Domain separation.** Every digest starts with a one-byte tag identifying what kind of hash it is,
  so a field commitment can never be replayed as a content hash.
- **Empty containers are committed as leaves.** Otherwise the difference between `{"tags":[]}` and
  `{}` is covered by nothing, and an empty container could be added or removed undetected.
- **Format version inside every digest,** so a future scheme change leaves old records verifiable
  under the rules in force when they were written, rather than appearing to break the whole chain.

## Rejected

**Storing hashes and salts as `byte[]` in the value types.** Arrays are mutable, which makes the
records only shallowly immutable and triggers `EI_EXPOSE_REP` correctly. Hex strings are used
instead; they are also the form these values take in the API and in export bundles, so the
conversion is not wasted.

**Suppressing `EI_EXPOSE_REP2` on `PayloadCommitter` broadly.** The injected `SecureRandom` genuinely
is meant to be shared, but the suppression is scoped to that one class and pattern, with the reason
written in `config/spotbugs-exclude.xml`, rather than disabling the detector.

# AI Assistance Log

Every task where AI assistance was used is recorded here with its intent, constraints, acceptance
criteria, and — most importantly — the disposition of what came back: **generated** (accepted as
produced), **edited** (accepted after human change), or **rejected** (discarded, with the reason).

The engineer owns correctness, maintainability, and production readiness. AI output is treated as a
draft from a fast but unaccountable colleague: useful, frequently wrong in ways that look right, and
never merged without being read.

## Rules for using AI on this repository

1. **No real data in prompts.** No production payloads, customer identifiers, account numbers,
   credentials, or key material. All fixtures are synthetic.
2. **No secrets in the repository.** Signing keys are generated locally, git-ignored, and scanned for
   in CI.
3. **High-impact changes require human sign-off** before merge, recorded in `docs/signoff/`. High
   impact means: the hash construction, database migrations, the append path, redaction, and export.
   These are the areas where a subtle error is either irreversible or invisible.
4. **Quality gates are not advisory.** Format check, static analysis, coverage floor, and tests all
   run in `mvn verify`. Suppressions must be narrow and carry a written justification
   (`config/spotbugs-exclude.xml`).

## Entries

| Date | Task | Disposition | Notes |
| --- | --- | --- | --- |
| 2026-08-24 | [0001 — Architecture and scope](0001-architecture-and-scope.md) | Edited | Initial design over-engineered; Merkle tree removed |
| 2026-08-24 | [0002 — Hashing core](0002-hashing-core.md) | Edited | Two defects found in review before merge |

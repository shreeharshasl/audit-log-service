# 0001 — Architecture and scope

Date: 2026-08-24
Disposition: **Edited** (substantially revised before acceptance)

## Intent

Produce an implementation plan for a tamper-evident audit log covering the three assignment
scenarios, and choose a stack.

## Constraints

- Append-only; no update or delete exposed by the API.
- Hash chain as the tamper-evidence mechanism, per the requirement.
- Must reach Scenarios B and C, not just A.

## Acceptance criteria

- Every open question in the requirement is either answered explicitly or listed as an assumption.
- The plan sequences work so that later scenarios do not force a rewrite of earlier ones.
- Known limitations are stated rather than omitted.

## What was rejected, and why

**A Merkle tree with signed checkpoints, inclusion proofs, and consistency proofs.** The first draft
proposed a full transparency-log design modelled on Certificate Transparency. It is a better system
in the abstract, but the requirement asks for a hash chain, no client needs `O(log n)` inclusion
proofs here, and the extra surface would have consumed the time budgeted for retention, redaction,
export, and compliance reporting. Rejected as scope creep. The hash chain was kept; signed
checkpoints were kept in reduced form because they address a real attack (below).

**The initial claim that a hash chain makes records tamper-proof.** It does not. A chain stored in
the database it protects is defeated by an attacker with write access who edits a record and then
recomputes every hash after it. The assignment's own validation ritual — edit a row, re-run verify —
only exercises the naive case. This was corrected in the plan, and the tail-recompute attack is now
scheduled as an explicit test rather than an unmentioned gap.

## What was edited

- **Test approach.** Any suite that only walks the happy path proves nothing about tamper evidence.
  The plan now requires an adversarial suite that bypasses the API and mutates PostgreSQL directly.
- **Pagination.** Offset pagination was replaced with keyset pagination: on an append-heavy table,
  `OFFSET` both degrades at depth and silently skips or repeats rows as new events arrive mid-scan.
- **Archival.** Added an `UNAUTHORIZED_ARCHIVE` violation type, because archival that is not itself
  checked against policy turns "archived" into a laundering channel for deletion.

## Decisions taken by the engineer

- Java 21 / Spring Boot / PostgreSQL.
- No Docker: the development machine had no container runtime, so Testcontainers was dropped in
  favour of a local PostgreSQL instance rather than spending the first hour on VM setup.
- Authentication out of scope, documented as a known gap rather than silently absent.
- Per-field salted commitments built into Scenario A up front (see ADR 0001).

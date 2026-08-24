# Tamper-Evident Audit Log Service

An append-only audit log that records events and makes after-the-fact modification detectable.

Java 21, Spring Boot 3.5, PostgreSQL 16.

## Status

| Area | State |
| --- | --- |
| Hashing core (canonical JSON, field commitments, hash chain) | Implemented, 74 tests |
| Persistence and append path | Implemented |
| Write / query / verify APIs | Implemented |
| Retention, redaction, export (Scenario B) | Not started |
| Compliance reporting (Scenario C) | Not started |

## Prerequisites

- JDK 21. This project pins Amazon Corretto 21; `scripts/env.sh` sets `JAVA_HOME` because
  `/usr/libexec/java_home` is unreliable on some macOS installs.
- Maven 3.9+
- PostgreSQL 16, running locally.

```bash
brew install maven postgresql@16
brew services start postgresql@16
createdb auditlog
createdb auditlog_test
```

## Run with Docker

Postgres, the HTTP API, and the verifier image:

```bash
docker compose up --build
```

http://localhost:8080/audit-service/api is the API. If local Postgres or another process already owns
5432 or 8080:

```bash
POSTGRES_HOST_PORT=5433 AUDIT_PORT=8081 docker compose up --build
```

The offline verifier is a one-shot CLI, not a long-running service:

```bash
docker compose run --rm verifier
```

## Build

```bash
source scripts/env.sh
mvn verify
```

`verify` runs the unit tests, the Spotless format check, SpotBugs, and a JaCoCo coverage floor of
90% lines / 85% branches on the hashing core. Dependency vulnerability scanning is opt-in via
`mvn -Psecurity verify` because it downloads the NVD feed and is slow.

## Modules

- **`audit-hashing-core`** — canonical serialization and the hash chain primitives. No Spring, no
  JDBC, no persistence. The offline verifier depends on this and nothing else, so a recipient
  checking an exported bundle runs exactly the bytes the service ran.
- **`audit-service`** — HTTP API, persistence, chain verification.
- **`audit-verifier-cli`** — standalone bundle verifier.

## How tamper evidence works

Each record stores two hashes:

- `contentHash` covers the record's own fields and a commitment to its payload.
- `chainHash = H(previousChainHash, contentHash)` links it to its predecessor.

Because each link folds in the previous link, altering record 10 changes the chain hash of record 10
and of every record after it. Verification recomputes both hashes from stored data and compares.

Payloads are not hashed as one blob. Each leaf position gets its own salted commitment:

```
commitment = H(fieldPath, salt, canonicalValue)
payloadRoot = H(count, [(fieldPath, commitment)] sorted by path)
```

This is what makes Scenario B's redaction possible without a chain rewrite: redacting a field drops
the value and its salt but keeps the commitment, so `payloadRoot` and every hash above it are
unchanged. The 256-bit salt is what makes the removal meaningful — a commitment to an unsalted
account number would be recoverable by brute force in seconds.

### What this does not protect against

**An attacker with write access to the database can rewrite the whole chain.** Edit record 500,
then recompute `contentHash` and `chainHash` for records 501 through N, and verification passes
cleanly. A hash chain stored in the database it protects cannot detect this by itself; the guarantee
is only as strong as the existence of a reference point the attacker could not reach.

The planned mitigation is periodic Ed25519-signed checkpoints over `(seq, chainHash)` written to a
separate store, so a rewritten tail contradicts a signature that already exists. That narrows the
gap but does not close it: an attacker who also holds the signing key can re-sign. Genuinely closing
it needs an external witness or write-once storage, which is out of scope here and named as a
limitation rather than quietly omitted.

### Other deliberate limitations

- **Authentication and authorization are out of scope.** Endpoints are open. In production,
  redaction, archival, and compliance reporting must sit behind authenticated, separately authorized
  roles, and every privileged call must itself be audited.
- **Redacted fields become unverifiable, not verified.** Once the salt is gone the commitment cannot
  be independently recomputed, so a log operator could substitute it. Only a checkpoint issued
  before the redaction pins the original value.
- **Payload numbers must be integers** in the range ±(2^53 − 1). Canonicalizing arbitrary floats
  reproducibly is subtle enough to be a real source of corrupt chains, and audit payloads have no
  need for them. Send decimals as strings or as integer minor units.

## Documentation

- `docs/adr/` — architecture decision records
- `docs/ai-usage/` — AI assistance log with dispositions and rationale

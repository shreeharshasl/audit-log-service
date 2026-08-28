# Setup and API guide

This is a tamper-evident, append-only audit log. Callers write events; the service stores them
with hashes that make later edits detectable. Records are never updated or deleted: privacy
requests redact fields in place, and retention archives by redacting remaining fields and setting
`archived`. Both leave the hash chain intact.

Every HTTP path sits under the context root **`/audit-service/api`**.

Base URL for a default local run:

```
http://localhost:8080/audit-service/api
```

Interactive OpenAPI UI: [http://localhost:8080/audit-service/api/swagger-ui.html](http://localhost:8080/audit-service/api/swagger-ui.html)

---

## 1. Set up the application

Pick **one** of the two paths below. Docker is the shortest if you have a container runtime.
Local JDK + PostgreSQL is what `mvn verify` uses.

### Option A — Docker Compose

You need Docker Desktop (or another Compose-capable engine).

From the repository root:

```bash
docker compose up --build
```

That starts:

| Container | Role |
| --- | --- |
| `auditlog-postgres` | PostgreSQL 16, databases `auditlog` and `auditlog_test` |
| `auditlog-service` | Spring Boot API on port 8080 |

Wait until the service is healthy, then open:

```
http://localhost:8080/audit-service/api/
```

You should see JSON listing the endpoints.

If port **5432** (Postgres) or **8080** (API) is already in use on your machine:

```bash
POSTGRES_HOST_PORT=5433 AUDIT_PORT=8081 docker compose up --build
```

Then the API is at `http://localhost:8081/audit-service/api`.

Compose defaults:

| Variable | Default | Meaning |
| --- | --- | --- |
| `AUDIT_DB_USER` | `audit` | Postgres user |
| `AUDIT_DB_PASSWORD` | `audit` | Postgres password |
| `POSTGRES_HOST_PORT` | `5432` | Host port mapped to Postgres |
| `AUDIT_PORT` | `8080` | Host port mapped to the API |
| `AUDIT_BOOTSTRAP_API_KEY` | `dev-local-key` | Seeded API key for the `bootstrap` client |

Flyway runs on startup and creates the schema. You do not run SQL by hand.

Stop with `Ctrl+C`, or `docker compose down`. Add `-v` only if you also want to wipe the database volume.

### Option B — local JDK, Maven, and PostgreSQL

**1. Install JDK 21, Maven 3.9+, and PostgreSQL 16.**

On macOS:

```bash
brew install maven postgresql@16
brew install --cask corretto@21
brew services start postgresql@16
```

**2. Create the two databases.**

```bash
createdb auditlog
createdb auditlog_test
```

`auditlog` is what the running service uses. `auditlog_test` is what integration tests use, so a
failed test cannot dirty the chain you are exercising by hand.

**3. Pin Java 21 on your shell.**

```bash
source scripts/env.sh
```

This sets `JAVA_HOME` to Amazon Corretto 21 if present, otherwise Temurin 21, and defaults:

- `AUDIT_DB_URL` → `jdbc:postgresql://localhost:5432/auditlog`
- `AUDIT_DB_USER` → your OS username

If your Postgres user is not your OS username, or it has a password:

```bash
export AUDIT_DB_USER=your_pg_user
export AUDIT_DB_PASSWORD=your_pg_password
```

**4. Build (optional but recommended the first time).**

```bash
source scripts/env.sh
mvn verify
```

This compiles all modules, runs the hashing-core unit tests, runs the service integration tests
against `auditlog_test`, and checks format / SpotBugs / coverage.

**5. Start the API.**

```bash
source scripts/env.sh
java -jar audit-service/target/audit-service-0.1.0-SNAPSHOT.jar
```

If you skipped `mvn verify`, package first:

```bash
source scripts/env.sh
mvn -pl audit-service -am package -DskipTests
java -jar audit-service/target/audit-service-0.1.0-SNAPSHOT.jar
```

The process listens on `8080` unless you set `AUDIT_PORT`. Schema migrations run automatically.

**6. Confirm it is up.**

```bash
curl -sS http://localhost:8080/audit-service/api/actuator/health
```

Expected: `{"status":"UP"}`.

### Environment variables (local run)

| Variable | Default | Used for |
| --- | --- | --- |
| `AUDIT_DB_URL` | `jdbc:postgresql://localhost:5432/auditlog` | JDBC URL for the running service |
| `AUDIT_DB_USER` | OS username (`scripts/env.sh`) | Database user |
| `AUDIT_DB_PASSWORD` | empty | Database password |
| `AUDIT_PORT` | `8080` | HTTP port |
| `AUDIT_BOOTSTRAP_API_KEY` | `dev-local-key` | Seeded API key (hashed on startup into `api_client`) |
| `AUDIT_OPEN_DOCS` | `true` | When true, Swagger UI does not require a key |
| `AUDIT_TEST_DB_URL` | `jdbc:postgresql://localhost:5432/auditlog_test` | Integration tests only |

---

## 2. How the APIs fit together

A typical session is:

1. Confirm the process is alive (`GET /` or health).
2. **Append** one or more events (`POST .../v1/audit-events`). Each append is assigned the next
   sequence number and linked to the previous record's chain hash.
3. **List** recent events (`GET .../v1/audit-events`) if you need a page of summaries.
4. **Fetch** a single sequence (`GET .../v1/audit-events/{seq}`) when you need payload and
   per-field commitments.
5. **Verify** the chain (`GET .../v1/chain/verify`) to recompute hashes from stored data and
   report tampering.
6. **Redact** individual payload fields (`POST .../v1/audit-events/{seq}/redactions`) when a
   privacy request arrives. The chain hashes do not change.
7. **Archive** records that have left the retention window (`POST .../v1/retention/apply`). This
   redacts remaining fields in place; it never deletes a row.
8. **Export** a range (`POST .../v1/exports`) and hand the JSON to the offline verifier.
9. **Report** (`GET .../v1/compliance/report`) for chain integrity, retention, redaction counts,
   and volume.

There is no update or delete of records. Archival is in-place redaction plus an `archived` flag.
Ordering in the chain is `seq`, assigned by the service, not `occurredAt` (that field is
caller-supplied and untrusted for ordering).

Payload rules that apply to append:

- JSON object (not a bare array or scalar).
- Numbers must be **integers** in ±(2^53 − 1). No floats. Send money as integer minor units or as a string.
- Duplicate object keys are rejected.
- Depth, leaf count, string length, and total canonical size are capped (see `audit.payload` in
  `application.yml`).

Authentication is **hashed API keys with roles**. Send `X-API-Key` (or `Authorization: Bearer`)
on every path except `/actuator/health`. The default local/Compose key is `dev-local-key`. The
plaintext is never stored: startup hashes it and upserts the `bootstrap` client with every role.
A missing or unknown key is `401 unauthorized`; a valid key without the role for that path is
`403 forbidden`. Redaction, retention policy/apply, and export create/read each append an
`audit.*` event so the privileged action is itself on the chain.

---

## 3. APIs, step by step

All examples assume the default base and the local bootstrap key:

```
BASE=http://localhost:8080/audit-service/api
API_KEY=dev-local-key
```

Use `-H "X-API-Key: $API_KEY"` on every call except health.

| Path | Role |
| --- | --- |
| `POST /v1/audit-events` | `APPEND` |
| `GET /v1/audit-events`, `GET /v1/audit-events/{seq}` | `READ` |
| `GET /v1/chain/verify` | `VERIFY` |
| `POST /v1/audit-events/{seq}/redactions` | `REDACT` |
| `/v1/retention/**` | `RETAIN` |
| `/v1/exports/**` | `EXPORT` |
| `GET /v1/compliance/report` | `COMPLIANCE` |
| `GET /` | any authenticated client |
| `GET /actuator/health` | none |

### 3.1 `GET /` — service index

**What it does.** Returns names and paths so a browser hitting the context root can find the real
endpoints. No database access.

```bash
curl -sS -H "X-API-Key: $API_KEY" http://localhost:8080/audit-service/api/
```

**You get.** JSON with `service`, `health`, `docs`, `appendEvents`, `getEvent`, `listEvents`,
`verifyChain`, `redactEvent`, `retentionPolicy`, `createExport`, `complianceReport`.

---

### 3.2 `GET /actuator/health` — liveness

**What it does.** Spring Boot health. Use this (or Docker's healthcheck) to decide whether the
process is ready.

```bash
curl -sS http://localhost:8080/audit-service/api/actuator/health
```

**Success.** `200` with `{"status":"UP"}`.

`GET /actuator/info` exists as well; it is empty unless you add info contributors.

---

### 3.3 `GET /swagger-ui.html` — OpenAPI UI

**What it does.** Browser UI over the generated OpenAPI spec. Useful for clicking through
request bodies. The spec JSON is at `/v3/api-docs`.

```bash
open http://localhost:8080/audit-service/api/swagger-ui.html
```

---

### 3.4 `POST /v1/audit-events` — append an event

**What it does, in order.**

1. Validates the JSON body (required fields, string lengths).
2. Canonicalizes `payload` and builds a salted commitment for every leaf field.
3. Takes a row lock on the chain head so two writers cannot fork the chain.
4. Rejects a reused `eventId` (`409`).
5. Assigns the next `seq`, hashes the header + payload root (`contentHash`), then hashes that
   together with the previous chain hash (`chainHash`).
6. Inserts the event, its field commitments, and advances the chain head.
7. Returns `201` with `Location` pointing at `GET /v1/audit-events/{seq}`.

**Request body**

| Field | Required | Meaning |
| --- | --- | --- |
| `eventType` | yes | What happened, e.g. `account.updated` (1–200 chars) |
| `actorId` | yes | Who did it |
| `resourceType` | yes | Kind of thing acted on, e.g. `account` |
| `resourceId` | yes | That thing's id |
| `occurredAt` | yes | When it happened in the caller's world (ISO-8601). Not used for chain order |
| `payload` | yes | JSON object of extra fields |
| `eventId` | no | Caller-chosen UUID. Send the same id on retry so a duplicate is `409` instead of a second row |

**Example — first event (service assigns `eventId`)**

```bash
curl -sS -D - -H "X-API-Key: $API_KEY" http://localhost:8080/audit-service/api/v1/audit-events \
  -H 'Content-Type: application/json' \
  -d '{
    "eventType": "account.updated",
    "actorId": "user-1",
    "resourceType": "account",
    "resourceId": "acc-1",
    "occurredAt": "2026-01-01T00:00:00Z",
    "payload": {"amount": 100, "currency": "USD"}
  }'
```

**Success (`201`).** Body includes `seq` (1 for an empty log), `eventId`, `recordedAt`,
`payloadRoot`, `contentHash`, `chainHash`, `hashVersion`. Header `Location` is the fetch URL.

**Example — second event, so the chain has a predecessor**

```bash
curl -sS -H "X-API-Key: $API_KEY" http://localhost:8080/audit-service/api/v1/audit-events \
  -H 'Content-Type: application/json' \
  -d '{
    "eventType": "account.updated",
    "actorId": "user-2",
    "resourceType": "account",
    "resourceId": "acc-1",
    "occurredAt": "2026-01-01T00:00:01Z",
    "payload": {"amount": 200, "currency": "USD"}
  }'
```

`seq` will be `2`. Its stored `previousChainHash` is the first event's `chainHash`.

**Example — caller-supplied `eventId` (safe retry)**

```bash
curl -sS -D - -H "X-API-Key: $API_KEY" http://localhost:8080/audit-service/api/v1/audit-events \
  -H 'Content-Type: application/json' \
  -d '{
    "eventId": "11111111-1111-1111-1111-111111111111",
    "eventType": "account.updated",
    "actorId": "user-3",
    "resourceType": "account",
    "resourceId": "acc-1",
    "occurredAt": "2026-01-01T00:00:02Z",
    "payload": {"amount": 300, "currency": "USD"}
  }'
```

Repeating the same `eventId` returns **`409 duplicate_event`**.

**Common failures**

| Status | `error` | When |
| --- | --- | --- |
| 400 | `validation_failed` | Missing/blank required fields |
| 400 | `invalid_payload` | Float numbers, oversized payload, values the hasher rejects |
| 400 | `malformed_request` | Body is not JSON, or duplicate keys in an object |
| 409 | `duplicate_event` | `eventId` already stored |

Floats are rejected on purpose:

```bash
curl -sS -D - -H "X-API-Key: $API_KEY" http://localhost:8080/audit-service/api/v1/audit-events \
  -H 'Content-Type: application/json' \
  -d '{
    "eventType": "account.updated",
    "actorId": "user-1",
    "resourceType": "account",
    "resourceId": "acc-1",
    "occurredAt": "2026-01-01T00:00:00Z",
    "payload": {"amount": 10.5}
  }'
```

---

### 3.5 `GET /v1/audit-events` — list events (keyset)

**What it does.** Returns a **newest-first** page of summaries. It does not return payloads or
field commitments (use fetch-by-seq for those). Pagination is a keyset on `seq`, not `OFFSET`,
so a page stays stable as new events arrive.

**Query parameters**

| Param | Required | Meaning |
| --- | --- | --- |
| `limit` | no | Page size. Default 50, clamped to max 200 |
| `beforeSeq` | no | Exclusive cursor: only rows with `seq` strictly less than this. Omit on the first page |
| `actorId` | no | Exact match |
| `eventType` | no | Exact match |
| `resourceType` | no | Exact match |
| `resourceId` | no | Exact match; **requires** `resourceType` |

**Step 1 — first page**

```bash
curl -sS -H "X-API-Key: $API_KEY" 'http://localhost:8080/audit-service/api/v1/audit-events?limit=2'
```

**You get.**

```json
{
  "items": [ { "seq": 3, "...": "..." }, { "seq": 2, "...": "..." } ],
  "hasMore": true,
  "nextBeforeSeq": 2
}
```

Each item has `seq`, `eventId`, `eventType`, `actorId`, `resourceType`, `resourceId`,
`occurredAt`, `recordedAt`, `contentHash`, `chainHash`, `hashVersion`, `archived`.

If `hasMore` is `false`, you are on the last page and `nextBeforeSeq` is omitted.

**Step 2 — next page**

Pass the previous `nextBeforeSeq` as `beforeSeq`:

```bash
curl -sS -H "X-API-Key: $API_KEY" 'http://localhost:8080/audit-service/api/v1/audit-events?beforeSeq=2&limit=2'
```

**Filters**

```bash
curl -sS -H "X-API-Key: $API_KEY" 'http://localhost:8080/audit-service/api/v1/audit-events?actorId=user-1&limit=50'
curl -sS -H "X-API-Key: $API_KEY" 'http://localhost:8080/audit-service/api/v1/audit-events?eventType=account.updated'
curl -sS -H "X-API-Key: $API_KEY" 'http://localhost:8080/audit-service/api/v1/audit-events?resourceType=account&resourceId=acc-1'
```

`resourceId` without `resourceType` returns **`400 invalid_request`**. `beforeSeq` below 1 does
the same.

An empty log returns `{"items":[],"hasMore":false}`.

---

### 3.6 `GET /v1/audit-events/{seq}` — fetch one record

**What it does.** Loads sequence `seq` and every stored field commitment. This is the record you
would hand to an offline verifier: header, canonical payload bytes, hashes, and per-field salts.

```bash
curl -sS -H "X-API-Key: $API_KEY" http://localhost:8080/audit-service/api/v1/audit-events/1
```

**Success (`200`).** In addition to the list-summary fields:

| Field | Meaning |
| --- | --- |
| `payload` | Canonical payload parsed back to JSON (keys sorted) |
| `canonicalPayload` | Exact text the hashes cover |
| `payloadRoot` | Hash of all field commitments |
| `previousChainHash` | Predecessor's `chainHash`, or 64 zero hex digits for `seq` 1 |
| `commitments[]` | One entry per leaf: `path` (JSON Pointer), `kind`, `salt`, `commitment`, `redacted` |
| `archived` | `true` after retention has redacted remaining fields in place |
| `archivedAt` | When it was archived; omitted/`null` otherwise |

**Missing seq.** `404 not_found`, e.g. `/v1/audit-events/9999`.

---

### 3.7 `GET /v1/chain/verify` — recompute the hash chain

**What it does.** Does **not** trust stored hashes. For each record in the range it recomputes
`contentHash`, `chainHash`, the link to the predecessor, the payload root, and each field
commitment, then reports mismatches.

This is how you detect a row edited in PostgreSQL. It cannot, by itself, detect an attacker who
rewrites a record **and** recomputes every later hash (that needs signed checkpoints, not built
yet).

**Query parameters**

| Param | Required | Meaning |
| --- | --- | --- |
| `fromSeq` | no | First sequence to check. Default `1` |
| `toSeq` | no | Last sequence to check. Default: current chain head |

**Step 1 — verify everything**

```bash
curl -sS -H "X-API-Key: $API_KEY" http://localhost:8080/audit-service/api/v1/chain/verify
```

**Intact chain.**

```json
{
  "intact": true,
  "fromSeq": 1,
  "toSeq": 2,
  "recordsChecked": 2,
  "violations": []
}
```

**Step 2 — verify a slice**

```bash
curl -sS -H "X-API-Key: $API_KEY" 'http://localhost:8080/audit-service/api/v1/chain/verify?fromSeq=1&toSeq=2'
```

`fromSeq` must be ≥ 1 and ≤ `toSeq`, or you get `400 invalid_request`.

**If something was tampered with.** `intact` is `false` and `violations` lists each problem:

| `type` | Meaning |
| --- | --- |
| `CONTENT_HASH_MISMATCH` | Header fields or payload root no longer hash to the stored content hash |
| `CHAIN_HASH_MISMATCH` | Stored chain hash does not match predecessor + content |
| `BROKEN_LINK` | This row's `previousChainHash` is not the previous row's `chainHash` |
| `UNAUTHORIZED_ARCHIVE` | A sequence number is missing. Records can only be archived in place; a deleted row is tampering |
| `PAYLOAD_ROOT_MISMATCH` | Stored commitments do not reproduce `payloadRoot` |
| `FIELD_COMMITMENT_INVALID` | A leaf value no longer matches its salted commitment |

---

### 3.8 `POST /v1/audit-events/{seq}/redactions` — redact payload fields

**What it does.** Deletes the value and the salt at each JSON Pointer, keeps the commitment.
`payloadRoot`, `contentHash`, and every later `chainHash` are unchanged. Redacted fields report as
`redacted: true` with `salt: null` and are unverifiable, not verified.

A nested object that would become `{}` after the last child is removed is pruned, so the flattener
does not treat that empty object as a new uncommitted field. Array elements are replaced with
`null` rather than removed, so later indexes keep their paths.

This endpoint is separately authorized (`ROLE_REDACT`). The call itself is written to the chain as
`audit.redaction` with `actorId` set to the API client name.

**Request body**

| Field | Required | Meaning |
| --- | --- | --- |
| `paths` | yes | JSON Pointers, e.g. `["/account/number"]`. A parent path redacts every nested leaf |

```bash
curl -sS -H "X-API-Key: $API_KEY" http://localhost:8080/audit-service/api/v1/audit-events/1/redactions \
  -H 'Content-Type: application/json' \
  -d '{"paths": ["/account/number"]}'
```

**Success (`200`).** The updated record, same shape as fetch-by-seq. Chain verify still returns
`intact: true`.

**Common failures**

| Status | `error` | When |
| --- | --- | --- |
| 404 | `not_found` | Sequence does not exist, or the path matches no stored commitment |
| 409 | `already_redacted` | That path is already redacted |
| 409 | `event_archived` | The record was archived; remaining fields are already gone |
| 400 | `invalid_request` | Empty `paths`, or a pointer that is not valid JSON Pointer syntax |

---

### 3.9 `GET` / `PUT /v1/retention/policy` — retention window

**What it does.** Reads or replaces the single-row policy. `retainDays` is the live window;
records whose `recordedAt` is older than that are eligible for archival. Default is 365.

```bash
curl -sS -H "X-API-Key: $API_KEY" http://localhost:8080/audit-service/api/v1/retention/policy
curl -sS -X PUT -H "X-API-Key: $API_KEY" http://localhost:8080/audit-service/api/v1/retention/policy \
  -H 'Content-Type: application/json' \
  -d '{"retainDays": 90}'
```

`retainDays` must be between 1 and 36500.

---

### 3.10 `POST /v1/retention/apply` — archive eligible records

**What it does.** For each unarchived record older than the policy window: redacts every remaining
field, sets `canonicalPayload` to `{}`, sets `archived=true`. Sequence numbers and hashes stay.
This is the only supported way to forget payload data for retention. `DELETE FROM audit_event` is
detected as `UNAUTHORIZED_ARCHIVE`.

```bash
curl -sS -X POST -H "X-API-Key: $API_KEY" http://localhost:8080/audit-service/api/v1/retention/apply
```

**Success (`200`).** `{ "archivedCount": 3, "retainDays": 90, "cutoff": "..." }`.

---

### 3.11 `POST /v1/exports` — export a chain slice

**What it does.** Loads `fromSeq`..`toSeq` (inclusive, must be gap-free), hashes an export
manifest over `(seq, contentHash, chainHash)` with domain tag `0x06`, stores metadata, and
returns a JSON bundle a recipient can verify without this service.

```bash
curl -sS -H "X-API-Key: $API_KEY" http://localhost:8080/audit-service/api/v1/exports \
  -H 'Content-Type: application/json' \
  -d '{"fromSeq": 1, "toSeq": 2}' \
  -o bundle.json
```

**Success (`201`).** Body is the bundle (save this file) plus `exportId` and `createdAt`.
`Location` is `GET /v1/exports/{exportId}`, which regenerates the bundle from the live store
(payloads and salts reflect any later redaction; hashes and the manifest do not change).

A range with a missing sequence returns **`409 incomplete_range`**.

**Offline verification**

```bash
java -jar audit-verifier-cli/target/audit-verifier.jar bundle.json
# or
docker compose run --rm -v "$PWD/bundle.json:/bundle.json:ro" verifier /bundle.json
```

Exit `0` means the records in the file are internally consistent. Exit `1` lists violations.
The verifier depends only on `audit-hashing-core`.

---

### 3.12 `GET /v1/compliance/report` — Scenario C

**What it does.** One document covering:

- chain integrity for the whole log
- retention: eligible unarchived count vs the current policy (`compliant` is true when that count is 0)
- redaction: how many fields and how many events have at least one redacted field
- volume: total events and counts by `eventType`

```bash
curl -sS -H "X-API-Key: $API_KEY" http://localhost:8080/audit-service/api/v1/compliance/report
```

Requires `ROLE_COMPLIANCE`. Privileged writes elsewhere on the chain (`audit.redaction`,
`audit.retention.*`, `audit.export.*`) show up in `volume.byEventType`.

---

## 4. Error envelope

Failures (except a raw framework 404 outside the context root) look like:

```json
{
  "timestamp": "2026-08-24T22:14:35.457966Z",
  "status": 400,
  "error": "validation_failed",
  "message": "request is not valid",
  "details": ["actorId must not be null"]
}
```

`details` is omitted when empty. `401 unauthorized` is a missing or unknown API key.
`403 forbidden` is a known key without the role for that path.

---

## 5. Worked walkthrough

Run these in order against an empty `auditlog` database (or a fresh Compose volume).

```bash
BASE=http://localhost:8080/audit-service/api
API_KEY=dev-local-key

# 1. Alive?
curl -sS "$BASE/actuator/health"

# 2. Write two events
curl -sS -H "X-API-Key: $API_KEY" "$BASE/v1/audit-events" -H 'Content-Type: application/json' -d '{
  "eventType": "account.updated",
  "actorId": "user-1",
  "resourceType": "account",
  "resourceId": "acc-1",
  "occurredAt": "2026-01-01T00:00:00Z",
  "payload": {"amount": 100, "currency": "USD"}
}'

curl -sS -H "X-API-Key: $API_KEY" "$BASE/v1/audit-events" -H 'Content-Type: application/json' -d '{
  "eventType": "account.updated",
  "actorId": "user-2",
  "resourceType": "account",
  "resourceId": "acc-1",
  "occurredAt": "2026-01-01T00:00:01Z",
  "payload": {"amount": 200, "currency": "USD"}
}'

# 3. List newest first
curl -sS -H "X-API-Key: $API_KEY" "$BASE/v1/audit-events?limit=50"

# 4. Full record + commitments for seq 1
curl -sS -H "X-API-Key: $API_KEY" "$BASE/v1/audit-events/1"

# 5. Chain should be intact
curl -sS -H "X-API-Key: $API_KEY" "$BASE/v1/chain/verify"

# 6. Redact one field; hashes stay the same
curl -sS -H "X-API-Key: $API_KEY" "$BASE/v1/audit-events/1/redactions" -H 'Content-Type: application/json' \
  -d '{"paths":["/amount"]}'

# 7. Export seq 1-2 and verify offline (after mvn -pl audit-verifier-cli -am package)
curl -sS -H "X-API-Key: $API_KEY" "$BASE/v1/exports" -H 'Content-Type: application/json' \
  -d '{"fromSeq":1,"toSeq":2}' -o bundle.json
java -jar audit-verifier-cli/target/audit-verifier.jar bundle.json

# 8. Compliance snapshot
curl -sS -H "X-API-Key: $API_KEY" "$BASE/v1/compliance/report"
```

---

## 6. Not implemented yet

- Signed checkpoints (a rewritten tail can still pass verify)
- A public API for creating and rotating API keys (seed via `AUDIT_BOOTSTRAP_API_KEY` or insert into `api_client`)

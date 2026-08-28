# Production deployment

This is what you need to run the tamper-evident audit log as a real service, not a local demo.
Compose (`docker compose up`) and the defaults in `application.yml` are for development. They are
not a production topology.

The runtime is two processes plus PostgreSQL:

| Piece | Role |
| --- | --- |
| PostgreSQL 16 | Source of truth for the chain, field commitments, retention policy, export metadata, and hashed API clients |
| `audit-service` | Spring Boot HTTP API (context path `/audit-service/api`) |
| `audit-verifier-cli` | Optional one-shot JAR. Recipients verify an export bundle without the database. It is not a long-running service |

Callers reach the API only. They never talk to Postgres.

---

## 1. What production still does not provide

Ship with these constraints named, not discovered later:

- **No signed checkpoints.** An attacker with write access to Postgres can rewrite a record and
  recompute every later `contentHash` / `chainHash`. `GET /v1/chain/verify` will still report
  `intact: true`. Detecting that needs an external witness (planned Ed25519 checkpoints, not built).
- **No public key-management API.** Clients are seeded with `AUDIT_BOOTSTRAP_API_KEY` or inserted
  into `api_client`. Rotation is a SQL (or ops) procedure.
- **Redacted fields are unverifiable.** Dropping the salt hides the value; it also means the
  commitment can no longer be recomputed from the payload.
- **Appends serialize on one row.** `SELECT ... FOR UPDATE` on `audit_chain_head` prevents a forked
  chain. Throughput is one append (or privileged write) at a time per database, not per replica.
- **API keys are SHA-256 lookups**, not a password KDF. Keys must be long, random, and unique.
  Treat them like bearer tokens.

If those limits are unacceptable for the threat model, do not treat verify-on-the-same-database as
tamper proof.

---

## 2. Runtime requirements

| Dependency | Version / notes |
| --- | --- |
| JRE | 21 (Amazon Corretto or Eclipse Temurin). The image uses `eclipse-temurin:21-jre` |
| PostgreSQL | **16**. Integration tests and the append path depend on `SELECT ... FOR UPDATE` and `timestamptz` microsecond precision. Do not substitute H2, SQLite, or an in-memory store |
| Maven | 3.9+ only if you build from source. Not required to *run* a packaged JAR |
| TLS terminator | Reverse proxy, load balancer, or API gateway. The application does not terminate HTTPS itself |

Network:

- Postgres must not be reachable from the public internet.
- The API should be reachable only through TLS (443) with the context path preserved:
  `https://<host>/audit-service/api/...`
- Health checks hit `GET /audit-service/api/actuator/health` and do **not** send an API key.

---

## 3. Build the artifacts

From the repository root, on JDK 21:

```bash
mvn -pl audit-service,audit-verifier-cli -am package
```

That produces:

- `audit-service/target/audit-service-0.1.0-SNAPSHOT.jar` — the API
- `audit-verifier-cli/target/audit-verifier.jar` — offline verifier

Or build the production image from the repo-root `Dockerfile` (target `audit-service`). The
verifier image is target `verifier`. Do not publish an image that still contains
`dev-local-key` as a baked-in secret; pass secrets at runtime.

`mvn verify` is the quality gate (tests, Spotless, SpotBugs, JaCoCo). Run it in CI before a
release candidate. It needs a local PostgreSQL and database `auditlog_test`.

---

## 4. Database

### 4.1 Provision

Create one application database (name is yours; the JDBC URL must match):

```sql
CREATE DATABASE auditlog;
```

Create a dedicated role with a strong password. Grant it only on this database. Do not use the
Postgres superuser as `AUDIT_DB_USER`.

The service runs **Flyway on startup**. It applies, in order:

| Migration | What it creates |
| --- | --- |
| `V1__create_audit_log.sql` | `audit_chain_head`, `audit_event`, `audit_field_commitment` |
| `V2__retention_archive_export.sql` | archive columns, `audit_retention_policy`, `audit_export` |
| `V3__api_clients.sql` | `api_client` |

Never edit an applied migration. Schema changes go in a new `V4__...sql` under
`audit-service/src/main/resources/db/migration`.

### 4.2 Hard rules for this schema

- **`canonical_payload` is `text`, never `jsonb`.** `jsonb` reorders keys and normalizes values,
  which breaks the bytes the hashes cover.
- **Never `DELETE` or `TRUNCATE` `audit_event`.** A missing sequence is reported as
  `UNAUTHORIZED_ARCHIVE`. Retention archives in place (`archived = true` plus field redaction).
- Take logical backups (or snapshots) of the whole database. Restoring a partial dump can look
  like tampering.
- Point-in-time recovery is worth enabling: this database *is* the audit log.

### 4.3 JDBC URL

Set `AUDIT_DB_URL` explicitly. Production should require TLS to Postgres, for example:

```
jdbc:postgresql://db.internal:5432/auditlog?sslmode=require
```

Do not rely on the compile-time default username (`harsha`) or an empty password.

---

## 5. Configuration

All of these are environment variables. None of the production secrets belong in the image or in
git.

### Required

| Variable | Purpose |
| --- | --- |
| `AUDIT_DB_URL` | JDBC URL of the production database |
| `AUDIT_DB_USER` | Database user |
| `AUDIT_DB_PASSWORD` | Database password |

### Strongly recommended

| Variable | Production value | Why |
| --- | --- | --- |
| `AUDIT_BOOTSTRAP_API_KEY` | A high-entropy secret **or empty** | Default is `dev-local-key`, which is public in this repo. Empty skips seeding; you must insert clients yourself |
| `AUDIT_OPEN_DOCS` | `false` | Default `true` leaves Swagger UI and `/v3/api-docs` unauthenticated |
| `AUDIT_PORT` | `8080` (container) or as the platform requires | HTTP listen port *inside* the process. TLS stays on the proxy |

### Optional (defaults are already set)

| Variable / property | Default | Notes |
| --- | --- | --- |
| Hikari `maximum-pool-size` | 10 | Raise only if you have the Postgres `max_connections` headroom. Append still queues on one row lock |
| `audit.payload.*` | depth 8, 256 leaves, 64 KiB canonical, 8 KiB strings | Raise only with a measured need; these cap hash work and request size |
| `audit.query.max-page-size` | 200 | List API clamp |

There is no Spring profile named `prod` in the repo. Production is “default profile plus env
overrides.” Do not copy `application-test.yml` (it points at `auditlog_test` and a test key).

---

## 6. Authentication and clients

Callers send the raw key on every request except health:

```
X-API-Key: <key>
```

or `Authorization: Bearer <key>`. The service stores **SHA-256(key) as lowercase hex**, never the
key.

Roles and the paths they unlock:

| Role | Paths |
| --- | --- |
| `APPEND` | `POST /v1/audit-events` |
| `READ` | `GET /v1/audit-events`, `GET /v1/audit-events/{seq}` |
| `VERIFY` | `GET /v1/chain/verify` |
| `REDACT` | `POST /v1/audit-events/{seq}/redactions` |
| `RETAIN` | `/v1/retention/**` |
| `EXPORT` | `/v1/exports`, `/v1/exports/{exportId}` |
| `COMPLIANCE` | `/v1/compliance/**` |

`GET /` requires any valid key. Missing/unknown key → `401 unauthorized`. Wrong role → `403
forbidden`.

### 6.1 Do not ship the demo bootstrap key

On startup, a non-blank `AUDIT_BOOTSTRAP_API_KEY` upserts a client named `bootstrap` with **every
role**. That is a break-glass admin key.

For production:

1. Generate a random key (32+ bytes, e.g. `openssl rand -base64 32`).
2. Put it in the secret store as `AUDIT_BOOTSTRAP_API_KEY` for the **first** boot so Flyway + seed
   succeed.
3. Create least-privilege clients (writer, reader, compliance, …).
4. Disable or rotate `bootstrap`:

```sql
UPDATE api_client SET enabled = false WHERE name = 'bootstrap';
```

Setting `AUDIT_BOOTSTRAP_API_KEY` to empty later does **not** disable an already-inserted
`bootstrap` row; it only skips the seed/refresh.

### 6.2 Insert a least-privilege client

Hash the plaintext key, then insert. `printf` avoids a trailing newline that would change the hash.

```bash
KEY=$(openssl rand -hex 32)
printf '%s' "$KEY" | shasum -a 256
# give KEY to the caller once; store only the hex hash
```

```sql
INSERT INTO api_client (client_id, name, key_hash, roles, enabled, created_at)
VALUES (
    gen_random_uuid(),
    'payments-writer',
    '<64-char-sha256-hex>',
    ARRAY['APPEND']::text[],
    true,
    now()
);
```

To rotate: insert a new row (new hash), cut callers over, then `enabled = false` on the old row.
There is no HTTP API for this.

Privileged HTTP actions (redact, retention policy/apply, export create/read) also append `audit.*`
events on the same chain, with `actorId` equal to the API client name.

---

## 7. How to run the API

### 7.1 Container (preferred)

Build from the repo root:

```bash
docker build --target audit-service -t audit-log-service:0.1.0 .
```

Run with secrets injected by the platform (not on the `docker run` command line in shared shells):

```text
AUDIT_DB_URL=jdbc:postgresql://...:5432/auditlog?sslmode=require
AUDIT_DB_USER=...
AUDIT_DB_PASSWORD=...
AUDIT_BOOTSTRAP_API_KEY=...          # first boot only, or omit after clients exist
AUDIT_OPEN_DOCS=false
AUDIT_PORT=8080
```

Healthcheck (already in the Dockerfile):

```
GET http://127.0.0.1:8080/audit-service/api/actuator/health
```

Expect `{"status":"UP"}`.

`docker-compose.yml` is a **local** stack: default DB password `audit`, bootstrap key
`dev-local-key`, Swagger left open. Do not point production DNS at it.

### 7.2 Bare JAR

```bash
export AUDIT_DB_URL=...
export AUDIT_DB_USER=...
export AUDIT_DB_PASSWORD=...
export AUDIT_OPEN_DOCS=false
java -jar audit-service/target/audit-service-0.1.0-SNAPSHOT.jar
```

Give the JVM a heap that fits the host (start around `-Xms512m -Xmx512m` and measure). The
process is stateless aside from the DB pool.

### 7.3 Replicas and load balancing

You may run **more than one** API instance against the **same** database. Session state is
stateless; the chain-head row lock is what keeps writers from forking. Put a load balancer in
front, sticky sessions off.

Do **not** give each replica its own database. That would be two logs, not one.

### 7.4 Kubernetes

Manifests live in `k8s/`. They start PostgreSQL 16 (StatefulSet) and the API (Deployment) in
namespace `auditlog`.

1. Build and load the image into the cluster:

```bash
docker build --target audit-service -t audit-log-service:0.1.0 .
# kind load docker-image audit-log-service:0.1.0
# minikube image load audit-log-service:0.1.0
```

2. Put real values in `k8s/secret.yaml` (`CHANGE_ME` is not a password). `AUDIT_DB_PASSWORD`
   must match `POSTGRES_PASSWORD` when using the in-cluster database.

3. Apply:

```bash
kubectl apply -k k8s/
kubectl -n auditlog rollout status deployment/auditlog-service
kubectl -n auditlog port-forward svc/auditlog-service 8080:8080
```

Health: `GET http://127.0.0.1:8080/audit-service/api/actuator/health`

Postgres is ClusterIP only. For a managed database, remove `postgres.yaml` from
`k8s/kustomization.yaml` and set `AUDIT_DB_URL` in `k8s/configmap.yaml` to that instance
(`sslmode=require`). Public HTTPS is optional: edit the host in `k8s/ingress.yaml` and apply it
once an ingress controller exists.

---

## 8. Edge and HTTP

- Terminate TLS at the proxy. Forward to `http://<app>:8080`.
- Keep the path prefix `/audit-service/api`. Changing `server.servlet.context-path` without
  updating every client and the Docker healthcheck will look like an outage.
- CSRF is disabled (API-key, stateless). Do not put a cookie session in front without revisiting
  that.
- `server.error.include-message` is `always`, so validation errors return a useful `message`.
  That is intentional for API callers; do not also expose `/actuator` beyond `health` and `info`.
- Set `AUDIT_OPEN_DOCS=false` so OpenAPI is not a public map of privileged routes.

---

## 9. Operations after go-live

| Task | How |
| --- | --- |
| Liveness | `GET /audit-service/api/actuator/health` |
| Chain integrity | `GET /v1/chain/verify` with a `VERIFY` key (on a schedule, alert if `intact` is false) |
| Retention | `PUT /v1/retention/policy` then a scheduled `POST /v1/retention/apply` with a `RETAIN` key. Apply redacts eligible rows in place; it does not delete |
| Privacy redaction | `POST /v1/audit-events/{seq}/redactions` with a `REDACT` key |
| Share a slice | `POST /v1/exports` → save JSON → `java -jar audit-verifier.jar bundle.json` (exit 0 = internally consistent) |
| Compliance snapshot | `GET /v1/compliance/report` with a `COMPLIANCE` key |

Backups: treat Postgres as the product. Test restore. After restore, run chain verify before
serving traffic.

Migrations: deploy a new app version that includes a new Flyway file; the first instance to start
applies it. Avoid two incompatible versions writing during a breaking migration.

---

## 10. Go-live checklist

- [ ] PostgreSQL 16 provisioned, not publicly reachable, TLS to the database enabled
- [ ] Dedicated DB role; `AUDIT_DB_URL` / `USER` / `PASSWORD` in a secret store
- [ ] First start completed Flyway through **v3** (`api_client` exists)
- [ ] `dev-local-key` is not a valid production key; `bootstrap` disabled or rotated
- [ ] Least-privilege clients created; keys delivered out of band, never logged
- [ ] `AUDIT_OPEN_DOCS=false`
- [ ] TLS on the public URL; health check configured on `/audit-service/api/actuator/health`
- [ ] Backup + restore drill succeeded; verify ran clean on the restored copy
- [ ] Scheduled chain verify and retention-apply jobs have keys with only those roles
- [ ] Load test accepted the single-row append lock (no assumption of linear scale-out on writes)
- [ ] Stakeholders accept the “same-DB hash chain is not a witness” limitation

When those boxes are ticked, the service is deployable: hashed API keys, role gates, Flyway schema,
in-place redaction/retention, export + offline verifier, and compliance reporting. What remains
out of scope is an independent checkpoint store and a first-class key-management API.

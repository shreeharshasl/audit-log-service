-- Initial schema for the tamper-evident audit log.

-- Enforces the output shape of Hex.encode at the storage boundary, so a malformed hash
-- fails on write rather than surfacing later as an unexplained verification failure.
CREATE DOMAIN sha256_hex AS text CHECK (VALUE ~ '^[0-9a-f]{64}$');

-- Single-row table whose lock serializes appends. Two concurrent writers that both read
-- the same previous chain hash would produce two records claiming the same predecessor,
-- forking the chain; SELECT ... FOR UPDATE on this row is what prevents that. It also
-- yields a gap-free sequence, which BIGSERIAL cannot promise because a rolled back
-- transaction still consumes its value.
CREATE TABLE audit_chain_head (
    id              smallint   PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    last_seq        bigint     NOT NULL CHECK (last_seq >= 0),
    last_chain_hash sha256_hex NOT NULL
);

INSERT INTO audit_chain_head (id, last_seq, last_chain_hash)
VALUES (1, 0, repeat('0', 64));

CREATE TABLE audit_event (
    seq             bigint      PRIMARY KEY CHECK (seq > 0),
    event_id        uuid        NOT NULL UNIQUE,
    event_type      text        NOT NULL CHECK (length(event_type) BETWEEN 1 AND 200),
    actor_id        text        NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 200),
    resource_type   text        NOT NULL CHECK (length(resource_type) BETWEEN 1 AND 200),
    resource_id     text        NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 200),
    occurred_at     timestamptz NOT NULL,
    recorded_at     timestamptz NOT NULL,
    -- text, deliberately not jsonb: jsonb reorders keys and normalizes numbers, which would
    -- destroy the exact canonical bytes the field commitments were computed over.
    canonical_payload text      NOT NULL,
    payload_root    sha256_hex  NOT NULL,
    content_hash    sha256_hex  NOT NULL,
    prev_chain_hash sha256_hex  NOT NULL,
    chain_hash      sha256_hex  NOT NULL,
    hash_version    integer     NOT NULL CHECK (hash_version > 0)
);

-- Query paths anticipated by the read API. Each is ordered by seq descending because
-- pagination is keyset on seq, never offset.
CREATE INDEX audit_event_recorded_at_idx ON audit_event (recorded_at DESC, seq DESC);
CREATE INDEX audit_event_actor_idx ON audit_event (actor_id, seq DESC);
CREATE INDEX audit_event_resource_idx ON audit_event (resource_type, resource_id, seq DESC);
CREATE INDEX audit_event_event_type_idx ON audit_event (event_type, seq DESC);

CREATE TABLE audit_field_commitment (
    event_seq      bigint     NOT NULL REFERENCES audit_event (seq),
    field_path     text       NOT NULL,
    leaf_kind      text       NOT NULL,
    -- Dropped, not blanked, when the field is redacted.
    salt_hex       sha256_hex,
    commitment_hex sha256_hex NOT NULL,
    redacted       boolean    NOT NULL DEFAULT false,
    PRIMARY KEY (event_seq, field_path),
    -- Mirrors the invariant enforced in FieldCommitment's constructor: a redacted field must
    -- not keep its salt, or the value stays recoverable by brute force.
    CONSTRAINT audit_field_commitment_salt_matches_redaction
        CHECK (redacted = (salt_hex IS NULL))
);

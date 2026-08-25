-- Retention, in-place archive, and export metadata.
--
-- Records are never deleted. Archiving redacts remaining payload fields and flags the row;
-- sequence numbers and hashes stay put so the chain does not grow a gap.

ALTER TABLE audit_event
    ADD COLUMN archived boolean NOT NULL DEFAULT false,
    ADD COLUMN archived_at timestamptz;

ALTER TABLE audit_event
    ADD CONSTRAINT audit_event_archived_at_matches
        CHECK (archived = (archived_at IS NOT NULL));

CREATE INDEX audit_event_unarchived_recorded_at_idx
    ON audit_event (recorded_at)
    WHERE archived = false;

-- Single-row policy. retain_days is the live window; older unarchived rows are eligible
-- for POST /v1/retention/apply.
CREATE TABLE audit_retention_policy (
    id          smallint    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    retain_days integer     NOT NULL CHECK (retain_days BETWEEN 1 AND 36500),
    updated_at  timestamptz NOT NULL
);

INSERT INTO audit_retention_policy (id, retain_days, updated_at)
VALUES (1, 365, timestamptz '2026-01-01 00:00:00+00');

CREATE TABLE audit_export (
    export_id     uuid        PRIMARY KEY,
    from_seq      bigint      NOT NULL CHECK (from_seq > 0),
    to_seq        bigint      NOT NULL CHECK (to_seq >= from_seq),
    record_count  integer     NOT NULL CHECK (record_count > 0),
    manifest_hash sha256_hex  NOT NULL,
    created_at    timestamptz NOT NULL
);

-- API clients. The plaintext key is never stored: only SHA-256(key) as hex.
-- Roles are application-defined names (APPEND, READ, ...); the service rejects unknown values.

CREATE TABLE api_client (
    client_id   uuid        PRIMARY KEY,
    name        text        NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 200),
    key_hash    sha256_hex  NOT NULL UNIQUE,
    roles       text[]      NOT NULL,
    enabled     boolean     NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL,
    CONSTRAINT api_client_roles_not_empty CHECK (cardinality(roles) >= 1),
    CONSTRAINT api_client_roles_known CHECK (
        roles <@ ARRAY['APPEND','READ','VERIFY','REDACT','RETAIN','EXPORT','COMPLIANCE']::text[]
    )
);

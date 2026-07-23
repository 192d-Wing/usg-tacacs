-- Authoritative JITPW lease state. Apply with a dedicated migration role;
-- the TACACS runtime role requires only SELECT, INSERT, and UPDATE.
CREATE SCHEMA IF NOT EXISTS jitpw;

CREATE TABLE jitpw.jit_leases (
    lease_id uuid PRIMARY KEY,
    eid text NOT NULL,
    icam_subject text NOT NULL,
    nad_identity text NOT NULL,
    authorization_groups jsonb NOT NULL DEFAULT '[]'::jsonb,
    verifier bytea NOT NULL,
    lookup_token text NOT NULL,
    idempotency_token text NOT NULL,
    request_fingerprint text NOT NULL,
    status text NOT NULL DEFAULT 'active',
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT jit_leases_eid_length CHECK (octet_length(eid) BETWEEN 1 AND 128),
    CONSTRAINT jit_leases_subject_length CHECK (octet_length(icam_subject) BETWEEN 1 AND 256),
    CONSTRAINT jit_leases_nad_length CHECK (octet_length(nad_identity) BETWEEN 1 AND 253),
    CONSTRAINT jit_leases_groups_array CHECK (jsonb_typeof(authorization_groups) = 'array'),
    CONSTRAINT jit_leases_verifier_length CHECK (octet_length(verifier) = 32),
    CONSTRAINT jit_leases_lookup_token_length CHECK (octet_length(lookup_token) = 64),
    CONSTRAINT jit_leases_idempotency_token_length CHECK (octet_length(idempotency_token) = 64),
    CONSTRAINT jit_leases_fingerprint_length CHECK (octet_length(request_fingerprint) = 64),
    CONSTRAINT jit_leases_status CHECK (status IN ('active', 'revoked', 'expired')),
    CONSTRAINT jit_leases_expiry CHECK (
        expires_at > issued_at
        AND expires_at <= issued_at + interval '15 minutes'
    ),
    CONSTRAINT jit_leases_revocation CHECK (
        (status = 'revoked' AND revoked_at IS NOT NULL)
        OR (status <> 'revoked' AND revoked_at IS NULL)
    ),
    UNIQUE (lookup_token),
    UNIQUE (idempotency_token)
);

CREATE UNIQUE INDEX jit_leases_one_active_eid_nad
    ON jitpw.jit_leases (eid, nad_identity)
    WHERE status = 'active';

CREATE INDEX jit_leases_expiry
    ON jitpw.jit_leases (expires_at)
    WHERE status = 'active';

COMMENT ON TABLE jitpw.jit_leases IS
    'Device-bound JITPW verifier leases; plaintext passwords and verifier keys are prohibited.';
COMMENT ON COLUMN jitpw.jit_leases.verifier IS
    'HMAC-SHA-256 verifier bound to canonical EID, NAD identity, and password.';


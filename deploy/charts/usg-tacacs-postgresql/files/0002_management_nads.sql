-- PostgreSQL-owned runtime NAD resources for the TACACS management API.
-- Apply with a migration role. The runtime role must not own these objects.
CREATE SCHEMA IF NOT EXISTS tacacs_management;

CREATE TABLE tacacs_management.nads (
    nad_id uuid PRIMARY KEY,
    name text NOT NULL,
    description text,
    source_address inet NOT NULL,
    authentication_mode text NOT NULL,
    secret_ref text,
    certificate_identities jsonb NOT NULL DEFAULT '[]'::jsonb,
    ownership text NOT NULL DEFAULT 'api',
    resource_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_by text NOT NULL,
    deleted_at timestamptz,
    deleted_by text,
    CONSTRAINT nads_name_length CHECK (octet_length(name) BETWEEN 1 AND 253),
    CONSTRAINT nads_name_canonical CHECK (
        name = lower(name)
        AND name ~ '^[a-z0-9][a-z0-9.-]*$'
    ),
    CONSTRAINT nads_description_length CHECK (
        description IS NULL OR octet_length(description) <= 1024
    ),
    CONSTRAINT nads_authentication_mode CHECK (
        authentication_mode IN ('legacy', 'tls')
    ),
    CONSTRAINT nads_certificate_identities_array CHECK (
        jsonb_typeof(certificate_identities) = 'array'
    ),
    CONSTRAINT nads_authentication_material CHECK (
        (
            authentication_mode = 'legacy'
            AND secret_ref IS NOT NULL
            AND octet_length(secret_ref) BETWEEN 1 AND 1024
            AND certificate_identities = '[]'::jsonb
        )
        OR
        (
            authentication_mode = 'tls'
            AND secret_ref IS NULL
            AND jsonb_array_length(certificate_identities) > 0
        )
    ),
    CONSTRAINT nads_ownership CHECK (ownership = 'api'),
    CONSTRAINT nads_resource_version_positive CHECK (resource_version > 0),
    CONSTRAINT nads_deletion_actor CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL)
        OR (deleted_at IS NOT NULL AND deleted_by IS NOT NULL)
    )
);

CREATE UNIQUE INDEX nads_active_name
    ON tacacs_management.nads (lower(name))
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX nads_active_source_address
    ON tacacs_management.nads (source_address)
    WHERE deleted_at IS NULL;

CREATE INDEX nads_active_updated
    ON tacacs_management.nads (updated_at, nad_id)
    WHERE deleted_at IS NULL;

CREATE TABLE tacacs_management.nad_idempotency (
    idempotency_token text PRIMARY KEY,
    request_fingerprint text NOT NULL,
    nad_id uuid NOT NULL REFERENCES tacacs_management.nads (nad_id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT nad_idempotency_token_length CHECK (
        octet_length(idempotency_token) = 64
    ),
    CONSTRAINT nad_idempotency_fingerprint_length CHECK (
        octet_length(request_fingerprint) = 64
    ),
    CONSTRAINT nad_idempotency_expiry CHECK (
        expires_at > created_at
        AND expires_at <= created_at + interval '24 hours'
    )
);

CREATE INDEX nad_idempotency_expiry
    ON tacacs_management.nad_idempotency (expires_at);

CREATE TABLE tacacs_management.nad_audit_events (
    event_id uuid PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    correlation_id uuid NOT NULL,
    actor text NOT NULL,
    action text NOT NULL,
    nad_id uuid NOT NULL,
    resource_version bigint NOT NULL,
    before_state jsonb,
    after_state jsonb,
    previous_event_hash bytea,
    event_hash bytea NOT NULL,
    hmac_signature bytea NOT NULL,
    CONSTRAINT nad_audit_action CHECK (
        action IN ('create', 'update', 'delete')
    ),
    CONSTRAINT nad_audit_actor_length CHECK (octet_length(actor) BETWEEN 1 AND 512),
    CONSTRAINT nad_audit_resource_version_positive CHECK (resource_version > 0),
    CONSTRAINT nad_audit_hash_length CHECK (
        octet_length(event_hash) = 32
        AND (
            previous_event_hash IS NULL
            OR octet_length(previous_event_hash) = 32
        )
    ),
    CONSTRAINT nad_audit_signature_length CHECK (octet_length(hmac_signature) = 32),
    CONSTRAINT nad_audit_state_transition CHECK (
        (action = 'create' AND before_state IS NULL AND after_state IS NOT NULL)
        OR (action = 'update' AND before_state IS NOT NULL AND after_state IS NOT NULL)
        OR (action = 'delete' AND before_state IS NOT NULL AND after_state IS NOT NULL)
    )
);

CREATE UNIQUE INDEX nad_audit_resource_version
    ON tacacs_management.nad_audit_events (nad_id, resource_version);

CREATE INDEX nad_audit_occurred
    ON tacacs_management.nad_audit_events (occurred_at, event_id);

CREATE FUNCTION tacacs_management.reject_nad_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'nad_audit_events is append-only';
END;
$$;

CREATE TRIGGER nad_audit_events_no_update
BEFORE UPDATE ON tacacs_management.nad_audit_events
FOR EACH ROW EXECUTE FUNCTION tacacs_management.reject_nad_audit_mutation();

CREATE TRIGGER nad_audit_events_no_delete
BEFORE DELETE ON tacacs_management.nad_audit_events
FOR EACH ROW EXECUTE FUNCTION tacacs_management.reject_nad_audit_mutation();

COMMENT ON TABLE tacacs_management.nads IS
    'API-owned runtime NAD metadata; plaintext TACACS secrets are prohibited.';
COMMENT ON COLUMN tacacs_management.nads.secret_ref IS
    'Opaque reference to externally managed secret material, never the secret value.';
COMMENT ON TABLE tacacs_management.nad_audit_events IS
    'Append-only, hash-chained, HMAC-authenticated NAD management audit trail.';

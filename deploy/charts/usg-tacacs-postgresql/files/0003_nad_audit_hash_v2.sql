-- Version the forensic NAD audit hash without rewriting historical evidence.
ALTER TABLE tacacs_management.nad_audit_events
    ADD COLUMN hash_version smallint;

UPDATE tacacs_management.nad_audit_events
   SET hash_version = 1;

ALTER TABLE tacacs_management.nad_audit_events
    ALTER COLUMN hash_version SET NOT NULL,
    ALTER COLUMN hash_version SET DEFAULT 2,
    ADD CONSTRAINT nad_audit_hash_version CHECK (hash_version IN (1, 2));

COMMENT ON COLUMN tacacs_management.nad_audit_events.hash_version IS
    'Hash format: v1 legacy resource transition; v2 authenticates all forensic metadata.';

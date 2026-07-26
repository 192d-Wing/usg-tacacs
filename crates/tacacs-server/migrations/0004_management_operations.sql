-- Durable management operations shared by all API replicas.
CREATE TABLE tacacs_management.operations (
    operation_id uuid PRIMARY KEY,
    kind text NOT NULL,
    status text NOT NULL,
    submitted_at timestamptz NOT NULL,
    completed_at timestamptz,
    error text,
    CONSTRAINT management_operation_kind CHECK (
        kind IN ('authorizationPolicyReload')
    ),
    CONSTRAINT management_operation_status CHECK (
        status IN ('running', 'succeeded', 'failed')
    ),
    CONSTRAINT management_operation_completion CHECK (
        (status = 'running' AND completed_at IS NULL AND error IS NULL)
        OR (status = 'succeeded' AND completed_at IS NOT NULL AND error IS NULL)
        OR (status = 'failed' AND completed_at IS NOT NULL)
    ),
    CONSTRAINT management_operation_error_length CHECK (
        error IS NULL OR octet_length(error) <= 4096
    )
);

CREATE INDEX management_operations_completed
    ON tacacs_management.operations (completed_at, operation_id)
    WHERE completed_at IS NOT NULL;

COMMENT ON TABLE tacacs_management.operations IS
    'Durable management operation state shared across Kubernetes replicas.';

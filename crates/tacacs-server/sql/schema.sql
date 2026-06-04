-- SPDX-License-Identifier: Apache-2.0
-- User store schema for SSH public key management.
--
-- NIST SP 800-53 Rev. 5 Controls:
--   AC-2  (Account Management)    - users table tracks enabled/disabled accounts
--   IA-5  (Authenticator Mgmt)    - user_ssh_keys stores managed public keys
--   IA-5(2) (PKI-Based Auth)      - key_type restricts to known-safe algorithms
--   AU-3  (Audit Record Content)  - created_at timestamps for key lifecycle audit

CREATE TABLE IF NOT EXISTS users (
    id         BIGSERIAL    PRIMARY KEY,
    username   TEXT         NOT NULL UNIQUE,
    enabled    BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_ssh_keys (
    id         BIGSERIAL    PRIMARY KEY,
    user_id    BIGINT       NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_type   TEXT         NOT NULL,
    key_data   TEXT         NOT NULL,
    comment    TEXT         NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, key_data)
);

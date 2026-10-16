-- migration:      0034
-- description:    create auth honeytokens table for active canary secret deception technology
-- author:         Platform Architecture & Security Team
-- date:           2026-10-16
-- depends_on:     0033_add_mtls_client_authentication.sql
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         MITRE ATT&CK DS0029 Deception Technology & NIST SP 800-160 Vol. 2 honeytoken tripwire defense (ADR 0041)

CREATE TABLE IF NOT EXISTS auth_honeytokens (
    id VARCHAR(64) PRIMARY KEY,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    token_prefix VARCHAR(32) NOT NULL DEFAULT 'ht_canary_',
    name VARCHAR(255) NOT NULL,
    org_id VARCHAR(64) NOT NULL REFERENCES auth_organizations(id) ON DELETE CASCADE,
    deployed_location VARCHAR(255) NULL,
    tripwire_count INT NOT NULL DEFAULT 0,
    last_tripped_at_ms BIGINT NULL,
    last_tripped_ip VARCHAR(64) NULL,
    last_tripped_user_agent VARCHAR(512) NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at_ms BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,

    CONSTRAINT auth_honeytokens_status_ck CHECK (status IN ('ACTIVE', 'TRIPPED', 'REVOKED')),
    CONSTRAINT auth_honeytokens_name_trimmed_ck CHECK (name = btrim(name) AND name <> '')
);

CREATE INDEX IF NOT EXISTS idx_auth_honeytokens_lookup 
    ON auth_honeytokens(token_hash) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_auth_honeytokens_org 
    ON auth_honeytokens(org_id, status) WHERE deleted_at IS NULL;

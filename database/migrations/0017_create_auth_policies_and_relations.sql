-- migration:      0017
-- description:    create auth policies and relations table for fine-grained rbac rebac
-- author:         Platform Architecture Team
-- date:           2026-09-22
-- depends_on:     0016
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         store fine-grained relation tuples for zanzibar-style permission evaluation

CREATE TABLE IF NOT EXISTS auth_relation_tuples (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES auth_organizations(id) ON DELETE CASCADE,
    subject_type VARCHAR(64) NOT NULL,
    subject_id VARCHAR(128) NOT NULL,
    relation VARCHAR(64) NOT NULL,
    object_type VARCHAR(64) NOT NULL,
    object_id VARCHAR(128) NOT NULL,
    
    -- ABAC dynamic constraints & policy payload
    conditions JSONB NOT NULL DEFAULT '{}'::jsonb,
    
    -- Status & Lifecycle
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    
    -- Time-bounded / Temporary grants
    expires_at TIMESTAMPTZ NULL,
    expires_at_ms BIGINT NULL,
    
    -- Audit & Concurrency
    granted_by VARCHAR(64) NULL,
    version BIGINT NOT NULL DEFAULT 1,
    created_at_ms BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,

    -- Explicit Named Constraints
    CONSTRAINT auth_relation_tuples_unique_uk UNIQUE (org_id, subject_type, subject_id, relation, object_type, object_id),
    CONSTRAINT auth_relation_tuples_status_ck CHECK (status IN ('ACTIVE', 'SUSPENDED', 'EXPIRED', 'REVOKED')),
    CONSTRAINT auth_relation_tuples_conditions_ck CHECK (jsonb_typeof(conditions) = 'object'),
    CONSTRAINT auth_relation_tuples_expiry_ck CHECK (expires_at IS NULL OR expires_at > created_at),
    CONSTRAINT auth_relation_tuples_subject_clean_ck CHECK (subject_id = btrim(subject_id) AND subject_id <> ''),
    CONSTRAINT auth_relation_tuples_object_clean_ck CHECK (object_id = btrim(object_id) AND object_id <> '')
);

CREATE INDEX IF NOT EXISTS idx_auth_relation_subject
    ON auth_relation_tuples(org_id, subject_type, subject_id) WHERE deleted_at IS NULL AND status = 'ACTIVE';

CREATE INDEX IF NOT EXISTS idx_auth_relation_object
    ON auth_relation_tuples(org_id, object_type, object_id) WHERE deleted_at IS NULL AND status = 'ACTIVE';

CREATE INDEX IF NOT EXISTS idx_auth_relation_lookup
    ON auth_relation_tuples(org_id, object_type, object_id, relation) WHERE deleted_at IS NULL AND status = 'ACTIVE';

CREATE INDEX IF NOT EXISTS idx_auth_relation_expiry
    ON auth_relation_tuples(expires_at_ms) WHERE expires_at_ms IS NOT NULL AND status = 'ACTIVE';

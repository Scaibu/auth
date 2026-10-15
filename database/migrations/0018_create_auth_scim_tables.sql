-- Migration: 0018_create_auth_scim_tables.sql
-- Description: SCIM 2.0 provisioning tables for enterprise directory synchronization (ADR 0024 / RFC 7643 / RFC 7644)

CREATE TABLE IF NOT EXISTS auth_scim_tokens (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES auth_organizations(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    description VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NULL,
    last_used_at_ms BIGINT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,

    CONSTRAINT auth_scim_tokens_status_ck CHECK (status IN ('ACTIVE', 'REVOKED'))
);

CREATE INDEX IF NOT EXISTS idx_auth_scim_tokens_hash 
    ON auth_scim_tokens(token_hash) WHERE deleted_at IS NULL AND status = 'ACTIVE';

CREATE TABLE IF NOT EXISTS auth_scim_external_mappings (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES auth_organizations(id) ON DELETE CASCADE,
    resource_type VARCHAR(32) NOT NULL,
    internal_id VARCHAR(64) NOT NULL,
    external_id VARCHAR(255) NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,

    CONSTRAINT auth_scim_external_mapping_uk UNIQUE (org_id, resource_type, external_id),
    CONSTRAINT auth_scim_external_resource_type_ck CHECK (resource_type IN ('user', 'group'))
);

CREATE INDEX IF NOT EXISTS idx_auth_scim_internal_map 
    ON auth_scim_external_mappings(org_id, resource_type, internal_id);

CREATE TABLE IF NOT EXISTS auth_groups (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES auth_organizations(id) ON DELETE CASCADE,
    display_name VARCHAR(255) NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    deleted_at TIMESTAMPTZ NULL,

    CONSTRAINT auth_groups_display_name_clean_ck CHECK (display_name = btrim(display_name) AND display_name <> '')
);

CREATE INDEX IF NOT EXISTS idx_auth_groups_org ON auth_groups(org_id) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS auth_group_members (
    id VARCHAR(64) PRIMARY KEY,
    group_id VARCHAR(64) NOT NULL REFERENCES auth_groups(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    added_at_ms BIGINT NOT NULL,

    CONSTRAINT auth_group_members_uk UNIQUE (group_id, user_id)
);

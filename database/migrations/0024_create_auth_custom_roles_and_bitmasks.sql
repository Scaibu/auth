-- migration:      0024
-- description:    create enterprise custom roles, 64-bit permission bitmask catalog, immutable trigger guards, and audit trail
-- author:         Platform Architecture & Security Team
-- date:           2026-10-15
-- depends_on:     0023_create_auth_passkeys.sql
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         enterprise zero-trust authorization with O(1) bitwise permission evaluation (ADR 0030)

-- Table 1: Standardized Permission Definitions Catalog (Storage Gate Source of Truth)
CREATE TABLE IF NOT EXISTS auth_permission_registry (
    permission_key VARCHAR(64) PRIMARY KEY,
    bit_position INT NOT NULL,
    bitmask NUMERIC(20, 0) NOT NULL,
    category VARCHAR(32) NOT NULL,
    description VARCHAR(255) NOT NULL,
    is_sensitive BOOLEAN NOT NULL DEFAULT FALSE,
    created_at_ms BIGINT NOT NULL,

    CONSTRAINT auth_permission_registry_key_trimmed_ck CHECK (permission_key = btrim(permission_key) AND permission_key <> ''),
    CONSTRAINT auth_permission_registry_bit_pos_uk UNIQUE (bit_position),
    CONSTRAINT auth_permission_registry_bitmask_uk UNIQUE (bitmask),
    CONSTRAINT auth_permission_registry_bit_pos_range_ck CHECK (bit_position >= 0 AND bit_position <= 62),
    CONSTRAINT auth_permission_registry_bitmask_pos_ck CHECK (bitmask > 0)
);

-- Table 2: Custom Enterprise Roles (Tenant Partitioned with Surrogate and Public IDs)
CREATE TABLE IF NOT EXISTS auth_custom_roles (
    id VARCHAR(64) PRIMARY KEY,
    public_id VARCHAR(64) NOT NULL,
    org_id VARCHAR(64) NOT NULL,
    name VARCHAR(64) NOT NULL,
    description VARCHAR(255) NOT NULL DEFAULT '',
    permission_mask NUMERIC(20, 0) NOT NULL DEFAULT 0,
    is_system_role BOOLEAN NOT NULL DEFAULT FALSE,
    version BIGINT NOT NULL DEFAULT 1,
    created_by VARCHAR(64) NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    deleted_at TIMESTAMP WITH TIME ZONE NULL,

    CONSTRAINT auth_custom_roles_public_id_uk UNIQUE (public_id),
    CONSTRAINT auth_custom_roles_tenant_id_uk UNIQUE (org_id, id),
    CONSTRAINT auth_custom_roles_tenant_name_uk UNIQUE (org_id, name),
    CONSTRAINT auth_custom_roles_name_trimmed_ck CHECK (name = btrim(name) AND name <> ''),
    CONSTRAINT auth_custom_roles_mask_nonneg_ck CHECK (permission_mask >= 0),
    CONSTRAINT auth_custom_roles_mask_range_ck CHECK (permission_mask <= 9223372036854775807),
    CONSTRAINT auth_custom_roles_version_positive_ck CHECK (version >= 1),
    CONSTRAINT auth_custom_roles_org_fk FOREIGN KEY (org_id)
        REFERENCES auth_organizations(id) ON DELETE CASCADE
);

-- Table 3: User Custom Role Bindings (Tenant Safe Composite Foreign Keys)
CREATE TABLE IF NOT EXISTS auth_user_custom_roles (
    id VARCHAR(64) PRIMARY KEY,
    public_id VARCHAR(64) NOT NULL,
    org_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    role_id VARCHAR(64) NOT NULL,
    version BIGINT NOT NULL DEFAULT 1,
    assigned_by VARCHAR(64) NULL,
    assigned_at_ms BIGINT NOT NULL,
    deleted_at TIMESTAMP WITH TIME ZONE NULL,

    CONSTRAINT auth_user_custom_roles_public_id_uk UNIQUE (public_id),
    CONSTRAINT auth_user_custom_roles_assignment_uk UNIQUE (org_id, user_id, role_id),
    CONSTRAINT auth_user_custom_roles_version_positive_ck CHECK (version >= 1),
    CONSTRAINT auth_user_custom_roles_org_fk FOREIGN KEY (org_id)
        REFERENCES auth_organizations(id) ON DELETE CASCADE,
    CONSTRAINT auth_user_custom_roles_user_fk FOREIGN KEY (user_id)
        REFERENCES auth_users(id) ON DELETE CASCADE,
    CONSTRAINT auth_user_custom_roles_role_fk FOREIGN KEY (org_id, role_id)
        REFERENCES auth_custom_roles(org_id, id) ON DELETE CASCADE
);

-- Table 4: Immutable Role Audit Trail (WORM / SOC 2 Type II Compliance)
CREATE TABLE IF NOT EXISTS auth_role_audit_logs (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL,
    actor_user_id VARCHAR(64) NOT NULL,
    action VARCHAR(32) NOT NULL,
    target_role_id VARCHAR(64) NOT NULL,
    target_user_id VARCHAR(64) NULL,
    previous_mask NUMERIC(20, 0) NULL,
    new_mask NUMERIC(20, 0) NULL,
    reason VARCHAR(255) NOT NULL DEFAULT '',
    created_at_ms BIGINT NOT NULL,

    CONSTRAINT auth_role_audit_logs_action_ck CHECK (
        action IN ('ROLE_CREATED', 'ROLE_UPDATED', 'ROLE_DELETED', 'ROLE_ASSIGNED', 'ROLE_REVOKED')
    ),
    CONSTRAINT auth_role_audit_logs_org_fk FOREIGN KEY (org_id)
        REFERENCES auth_organizations(id) ON DELETE CASCADE
);

-- Indexes for ultra-low latency query execution
CREATE INDEX IF NOT EXISTS idx_auth_custom_roles_org_lookup
    ON auth_custom_roles (org_id, deleted_at);

CREATE INDEX IF NOT EXISTS idx_auth_custom_roles_system
    ON auth_custom_roles (is_system_role) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_auth_user_custom_roles_user_lookup
    ON auth_user_custom_roles (org_id, user_id, deleted_at);

CREATE INDEX IF NOT EXISTS idx_auth_user_custom_roles_role_lookup
    ON auth_user_custom_roles (role_id, deleted_at);

CREATE INDEX IF NOT EXISTS idx_auth_role_audit_logs_org_time
    ON auth_role_audit_logs (org_id, created_at_ms DESC);

-- Trigger Function: Enforce Immutability of System Roles and Identifiers
CREATE OR REPLACE FUNCTION trg_enforce_role_immutability()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.is_system_role = TRUE AND (NEW.is_system_role = FALSE OR NEW.permission_mask <> OLD.permission_mask) THEN
        RAISE EXCEPTION 'System roles cannot be altered or modified in permission masks' USING ERRCODE = '23514';
    END IF;
    IF NEW.id <> OLD.id OR NEW.public_id <> OLD.public_id OR NEW.org_id <> OLD.org_id THEN
        RAISE EXCEPTION 'Identifiers (id, public_id, org_id) are strictly immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_auth_custom_roles_immutability ON auth_custom_roles;
CREATE TRIGGER trg_auth_custom_roles_immutability
    BEFORE UPDATE ON auth_custom_roles
    FOR EACH ROW
    EXECUTE FUNCTION trg_enforce_role_immutability();

-- Trigger Function: Append-Only Immutable Audit Log Enforcer
CREATE OR REPLACE FUNCTION trg_enforce_role_audit_append_only()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'Audit logs are strictly append-only; UPDATE operations are forbidden' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'DELETE' THEN
        IF current_setting('app.allow_audit_delete', true) <> 'on' THEN
            RAISE EXCEPTION 'Audit logs are strictly append-only; direct DELETE operations are forbidden' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_auth_role_audit_append_only ON auth_role_audit_logs;
CREATE TRIGGER trg_auth_role_audit_append_only
    BEFORE UPDATE OR DELETE ON auth_role_audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION trg_enforce_role_audit_append_only();

-- Seed System Default Canonical Permissions
INSERT INTO auth_permission_registry (permission_key, bit_position, bitmask, category, description, is_sensitive, created_at_ms)
VALUES
    ('ORG_READ', 0, 1, 'ORGANIZATION', 'Read organization details and metadata', FALSE, 1700000000000),
    ('ORG_UPDATE', 1, 2, 'ORGANIZATION', 'Update organization settings and profile', FALSE, 1700000000000),
    ('ORG_DELETE', 2, 4, 'ORGANIZATION', 'Delete or destroy organization', TRUE, 1700000000000),
    ('ORG_DOMAINS_MANAGE', 3, 8, 'ORGANIZATION', 'Claim, verify, and configure organization domains', TRUE, 1700000000000),
    ('USERS_READ', 8, 256, 'USER', 'View organization user directory and member profiles', FALSE, 1700000000000),
    ('USERS_INVITE', 9, 512, 'USER', 'Invite new members to the organization', FALSE, 1700000000000),
    ('USERS_ROLES_ASSIGN', 10, 1024, 'USER', 'Assign and revoke user custom roles and permissions', TRUE, 1700000000000),
    ('USERS_DELETE', 11, 2048, 'USER', 'Remove members and delete users from organization', TRUE, 1700000000000),
    ('API_KEYS_READ', 16, 65536, 'API_KEY', 'View and inspect API keys and allowlists', FALSE, 1700000000000),
    ('API_KEYS_CREATE', 17, 131072, 'API_KEY', 'Generate and provision new service API keys', TRUE, 1700000000000),
    ('API_KEYS_REVOKE', 18, 262144, 'API_KEY', 'Revoke active API keys and emergency disable', TRUE, 1700000000000),
    ('TELEMETRY_READ', 24, 16777216, 'TELEMETRY', 'Query and export traces, logs, and telemetry metrics', FALSE, 1700000000000),
    ('TELEMETRY_WRITE', 25, 33554432, 'TELEMETRY', 'Ingest and push telemetry spans, logs, and metrics', FALSE, 1700000000000),
    ('TELEMETRY_ADMIN', 26, 67108864, 'TELEMETRY', 'Manage retention policies, quotas, and ingestion filters', TRUE, 1700000000000),
    ('AUDIT_LOGS_READ', 32, 4294967296, 'AUDIT', 'Access enterprise immutable audit logs and compliance records', TRUE, 1700000000000),
    ('POLICIES_MANAGE', 33, 8589934592, 'SECURITY', 'Create, update, and manage ABAC/ReBAC relationship policies', TRUE, 1700000000000),
    ('SAML_MANAGE', 34, 17179869184, 'SECURITY', 'Configure SAML 2.0 SP/IdP federated identity providers', TRUE, 1700000000000),
    ('SCIM_MANAGE', 35, 34359738368, 'SECURITY', 'Configure SCIM 2.0 enterprise directory auto-provisioning', TRUE, 1700000000000),
    ('PASSKEYS_MANAGE', 36, 68719476736, 'SECURITY', 'Manage WebAuthn FIDO2 passkeys and security keys', TRUE, 1700000000000)
ON CONFLICT (permission_key) DO NOTHING;

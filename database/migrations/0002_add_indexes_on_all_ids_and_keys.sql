-- migration:      0002
-- description:    add indexes on all ids foreign keys and lookup columns
-- author:         Platform Architecture Team
-- date:           2026-08-16
-- depends_on:     0001
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         query performance optimization for tenant lookups and foreign key constraints

CREATE INDEX IF NOT EXISTS idx_auth_users_id_org_id ON auth_users(id, org_id);
CREATE INDEX IF NOT EXISTS idx_auth_api_keys_key_id_org_id ON auth_api_keys(key_id, org_id);
CREATE INDEX IF NOT EXISTS idx_auth_api_keys_prefix ON auth_api_keys(prefix);
CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_user_org ON auth_audit_logs(user_id, org_id);
CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_timestamp ON auth_audit_logs(timestamp_ms DESC);
CREATE INDEX IF NOT EXISTS idx_auth_resets_user_expires ON auth_password_resets(user_id, expires_at_ms);

-- migration:      0002
-- description:    drop indexes on all ids foreign keys and lookup columns
-- author:         Platform Architecture Team
-- date:           2026-08-16
-- depends_on:     0001
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         remove foreign key and lookup indexes

DROP INDEX IF EXISTS idx_auth_users_id_org_id;
DROP INDEX IF EXISTS idx_auth_api_keys_key_id_org_id;
DROP INDEX IF EXISTS idx_auth_api_keys_prefix;
DROP INDEX IF EXISTS idx_auth_audit_logs_user_org;
DROP INDEX IF EXISTS idx_auth_audit_logs_timestamp;
DROP INDEX IF EXISTS idx_auth_resets_user_expires;

-- migration:      0004
-- description:    remove organization user block columns and retention indexes
-- author:         Platform Architecture Team
-- date:           2026-08-16
-- depends_on:     0003
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert user blocking columns and retention indexes

DROP INDEX IF EXISTS idx_auth_users_blocked;
DROP INDEX IF EXISTS idx_auth_orgs_deleted_at;
DROP INDEX IF EXISTS idx_auth_users_deleted_at;
DROP INDEX IF EXISTS idx_auth_api_keys_deleted_at;
DROP INDEX IF EXISTS idx_auth_audit_logs_deleted_at;
DROP INDEX IF EXISTS idx_auth_resets_deleted_at;

ALTER TABLE auth_users DROP COLUMN IF EXISTS blocked;
ALTER TABLE auth_users DROP COLUMN IF EXISTS blocked_at;
ALTER TABLE auth_users DROP COLUMN IF EXISTS user_permissions;

-- migration:      0011
-- description:    remove retention purge partial indexes
-- author:         Platform Architecture Team
-- date:           2026-09-01
-- depends_on:     0010
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert retention purge partial indexes

DROP INDEX IF EXISTS idx_auth_orgs_deleted_at;
DROP INDEX IF EXISTS idx_auth_users_deleted_at;
DROP INDEX IF EXISTS idx_auth_api_keys_deleted_at;
DROP INDEX IF EXISTS idx_auth_audit_logs_deleted_at;
DROP INDEX IF EXISTS idx_auth_password_resets_deleted_at;
DROP INDEX IF EXISTS idx_auth_refresh_tokens_revoked_at;

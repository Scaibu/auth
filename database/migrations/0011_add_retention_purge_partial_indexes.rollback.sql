-- Rollback: 0011_add_retention_purge_partial_indexes.rollback.sql
DROP INDEX IF EXISTS idx_auth_orgs_deleted_at;
DROP INDEX IF EXISTS idx_auth_users_deleted_at;
DROP INDEX IF EXISTS idx_auth_api_keys_deleted_at;
DROP INDEX IF EXISTS idx_auth_audit_logs_deleted_at;
DROP INDEX IF EXISTS idx_auth_password_resets_deleted_at;
DROP INDEX IF EXISTS idx_auth_refresh_tokens_revoked_at;

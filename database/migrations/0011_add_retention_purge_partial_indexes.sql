-- Migration: 0011_add_retention_purge_partial_indexes.sql
-- Optimizes GDPR Article 17 automated 30-day cascade purge queries
-- Targets soft-deleted records older than 30 days without indexing live rows

CREATE INDEX IF NOT EXISTS idx_auth_orgs_deleted_at
  ON auth_organizations (deleted_at)
  WHERE deleted_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_auth_users_deleted_at
  ON auth_users (deleted_at)
  WHERE deleted_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_auth_api_keys_deleted_at
  ON auth_api_keys (deleted_at)
  WHERE deleted_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_deleted_at
  ON auth_audit_logs (deleted_at)
  WHERE deleted_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_auth_password_resets_deleted_at
  ON auth_password_resets (deleted_at)
  WHERE deleted_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_is_revoked
  ON auth_refresh_tokens (is_revoked)
  WHERE is_revoked = TRUE;

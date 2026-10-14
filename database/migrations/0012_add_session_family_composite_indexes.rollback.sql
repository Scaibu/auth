-- Rollback Migration: 0012_add_session_family_composite_indexes.rollback.sql
DROP INDEX IF EXISTS idx_refresh_tokens_user_family_active;
DROP INDEX IF EXISTS idx_refresh_tokens_family_active;
DROP INDEX IF EXISTS idx_refresh_families_user_active;

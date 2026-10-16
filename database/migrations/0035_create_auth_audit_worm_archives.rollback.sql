-- Rollback Migration 0035: Drop Immutable WORM Audit Archives

DROP INDEX IF EXISTS idx_auth_audit_worm_archives_status;
DROP INDEX IF EXISTS idx_auth_audit_worm_archives_range;
DROP TABLE IF EXISTS auth_audit_worm_archives;

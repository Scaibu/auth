-- migration:      0009
-- description:    drop mfa and recovery codes tables
-- author:         Platform Architecture Team
-- date:           2026-08-25
-- depends_on:     0008
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert mfa and recovery codes tables

DROP INDEX IF EXISTS idx_auth_recovery_codes_user_id;
DROP TABLE IF EXISTS auth_recovery_codes;

ALTER TABLE auth_users
  DROP COLUMN IF EXISTS mfa_enrolled_at_ms,
  DROP COLUMN IF EXISTS mfa_secret,
  DROP COLUMN IF EXISTS mfa_enabled;

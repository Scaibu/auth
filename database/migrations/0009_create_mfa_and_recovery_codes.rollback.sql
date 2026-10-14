DROP INDEX IF EXISTS idx_auth_recovery_codes_user_id;
DROP TABLE IF EXISTS auth_recovery_codes;

ALTER TABLE auth_users
  DROP COLUMN IF EXISTS mfa_enrolled_at_ms,
  DROP COLUMN IF EXISTS mfa_secret,
  DROP COLUMN IF EXISTS mfa_enabled;

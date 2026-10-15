-- migration:      0007
-- description:    remove api key expiration and usage tracking columns
-- author:         Platform Architecture Team
-- date:           2026-08-20
-- depends_on:     0006
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert api key expiration and usage columns

DROP INDEX IF EXISTS idx_auth_api_keys_expires_at;

ALTER TABLE auth_api_keys
  DROP COLUMN IF EXISTS expires_at_ms,
  DROP COLUMN IF EXISTS last_used_at_ms,
  DROP COLUMN IF EXISTS last_used_ip;

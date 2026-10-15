-- migration:      0008
-- description:    drop email verifications table
-- author:         Platform Architecture Team
-- date:           2026-08-22
-- depends_on:     0007
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert email verifications table

DROP INDEX IF EXISTS idx_auth_email_verifications_email;
DROP INDEX IF EXISTS idx_auth_email_verifications_user_id;
DROP TABLE IF EXISTS auth_email_verifications;

ALTER TABLE auth_users
  DROP COLUMN IF EXISTS email_verified;

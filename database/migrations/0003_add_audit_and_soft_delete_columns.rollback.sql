-- migration:      0003
-- description:    remove updated_at and deleted_at columns from auth tables
-- author:         Platform Architecture Team
-- date:           2026-08-16
-- depends_on:     0002
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert soft delete and updated_at column additions

ALTER TABLE auth_organizations DROP COLUMN IF EXISTS updated_at;
ALTER TABLE auth_organizations DROP COLUMN IF EXISTS deleted_at;

ALTER TABLE auth_users DROP COLUMN IF EXISTS updated_at;
ALTER TABLE auth_users DROP COLUMN IF EXISTS deleted_at;

ALTER TABLE auth_api_keys DROP COLUMN IF EXISTS updated_at;
ALTER TABLE auth_api_keys DROP COLUMN IF EXISTS deleted_at;

ALTER TABLE auth_audit_logs DROP COLUMN IF EXISTS updated_at;
ALTER TABLE auth_audit_logs DROP COLUMN IF EXISTS deleted_at;

ALTER TABLE auth_password_resets DROP COLUMN IF EXISTS updated_at;
ALTER TABLE auth_password_resets DROP COLUMN IF EXISTS deleted_at;

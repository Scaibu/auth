-- rollback:       0031
-- description:    rollback upgrade auth_signing_keys eddsa and multi-state key lifecycle
-- author:         Platform Architecture & Security Team
-- date:           2026-10-16
-- depends_on:     0031_upgrade_auth_signing_keys_eddsa.sql
-- reversible:     YES

DROP INDEX IF EXISTS idx_auth_signing_keys_lookup;
ALTER TABLE auth_signing_keys DROP CONSTRAINT IF EXISTS auth_signing_keys_revocation_ck;
ALTER TABLE auth_signing_keys DROP CONSTRAINT IF EXISTS auth_signing_keys_algorithm_ck;
ALTER TABLE auth_signing_keys DROP CONSTRAINT IF EXISTS auth_signing_keys_status_ck;
ALTER TABLE auth_signing_keys ADD CONSTRAINT auth_signing_keys_status_ck CHECK (status IN ('ACTIVE', 'RETIRED'));
ALTER TABLE auth_signing_keys 
    DROP COLUMN IF EXISTS revoked_reason,
    DROP COLUMN IF EXISTS revoked_at_ms,
    DROP COLUMN IF EXISTS expires_at_ms,
    DROP COLUMN IF EXISTS x,
    DROP COLUMN IF EXISTS crv;

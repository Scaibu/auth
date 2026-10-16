-- migration:      0031
-- description:    upgrade auth_signing_keys table with eddsa ed25519 support and multi-state key rotation lifecycle
-- author:         Platform Architecture & Security Team
-- date:           2026-10-16
-- depends_on:     0030_create_auth_asn_threat_intelligence.sql
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         RFC 8037 EdDSA Ed25519 asymmetric token signing and zero-downtime JWKS key rotation lifecycle (ADR 0038)
-- nullable_columns:
--   - crv: optional curve name, null for RSA keys, 'Ed25519' for OKP keys
--   - x: public key coordinate base64url encoded, null for RSA keys
--   - expires_at_ms: epoch timestamp for retired key grace period expiration, null for active or un-retired keys
--   - revoked_at_ms: epoch timestamp when a key is compromised and revoked, null for active or retired keys
--   - revoked_reason: audit explanation for key revocation, null for active or retired keys

ALTER TABLE auth_signing_keys 
    ADD COLUMN IF NOT EXISTS crv VARCHAR(32) NULL,
    ADD COLUMN IF NOT EXISTS x TEXT NULL,
    ADD COLUMN IF NOT EXISTS expires_at_ms BIGINT NULL,
    ADD COLUMN IF NOT EXISTS revoked_at_ms BIGINT NULL,
    ADD COLUMN IF NOT EXISTS revoked_reason VARCHAR(255) NULL;

ALTER TABLE auth_signing_keys DROP CONSTRAINT IF EXISTS auth_signing_keys_status_ck;
ALTER TABLE auth_signing_keys ADD CONSTRAINT auth_signing_keys_status_ck 
    CHECK (status IN ('ACTIVE', 'RETIRED', 'REVOKED'));

ALTER TABLE auth_signing_keys DROP CONSTRAINT IF EXISTS auth_signing_keys_algorithm_ck;
ALTER TABLE auth_signing_keys ADD CONSTRAINT auth_signing_keys_algorithm_ck 
    CHECK (
        (kty = 'RSA' AND alg = 'RS256' AND crv IS NULL AND x IS NULL) OR
        (kty = 'OKP' AND alg = 'EdDSA' AND crv = 'Ed25519' AND x IS NOT NULL)
    );

ALTER TABLE auth_signing_keys DROP CONSTRAINT IF EXISTS auth_signing_keys_revocation_ck;
ALTER TABLE auth_signing_keys ADD CONSTRAINT auth_signing_keys_revocation_ck 
    CHECK (
        (status != 'REVOKED' AND revoked_at_ms IS NULL AND revoked_reason IS NULL) OR
        (status = 'REVOKED' AND revoked_at_ms IS NOT NULL AND revoked_reason IS NOT NULL)
    );

CREATE INDEX IF NOT EXISTS idx_auth_signing_keys_lookup 
    ON auth_signing_keys(status, alg, created_at_ms DESC);

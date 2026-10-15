-- migration:      0023
-- description:    drop auth passkey credentials and challenges tables
-- author:         Platform Architecture Team
-- date:           2026-10-15
-- depends_on:     0022
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert webauthn fido2 passkeys schema

DROP TABLE IF EXISTS auth_passkey_challenges CASCADE;
DROP TABLE IF EXISTS auth_passkey_credentials CASCADE;

-- migration:      0019
-- description:    drop auth oidc tables
-- author:         Platform Architecture Team
-- date:           2026-09-28
-- depends_on:     0018
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert auth oidc tables

DROP TABLE IF EXISTS auth_signing_keys CASCADE;
DROP TABLE IF EXISTS auth_oauth_codes CASCADE;
DROP TABLE IF EXISTS auth_oauth_clients CASCADE;

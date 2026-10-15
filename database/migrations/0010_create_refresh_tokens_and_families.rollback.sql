-- migration:      0010
-- description:    drop refresh tokens and families tables
-- author:         Platform Architecture Team
-- date:           2026-08-28
-- depends_on:     0009
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert refresh tokens and families tables

DROP TABLE IF EXISTS auth_refresh_tokens;
DROP TABLE IF EXISTS auth_refresh_token_families;

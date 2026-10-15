-- migration:      0005
-- description:    drop token denylist table
-- author:         Platform Architecture Team
-- date:           2026-08-18
-- depends_on:     0004
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert token denylist table

DROP INDEX IF EXISTS idx_auth_token_denylist_exp;
DROP TABLE IF EXISTS auth_token_denylist;

-- migration:      0015
-- description:    drop blocked domains table
-- author:         Platform Architecture Team
-- date:           2026-09-18
-- depends_on:     0014
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert blocked domains table

DROP TABLE IF EXISTS auth_blocked_domains CASCADE;

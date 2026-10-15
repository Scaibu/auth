-- migration:      0017
-- description:    drop auth policies and relations table
-- author:         Platform Architecture Team
-- date:           2026-09-22
-- depends_on:     0016
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert auth policies and relations table

DROP TABLE IF EXISTS auth_relation_tuples CASCADE;

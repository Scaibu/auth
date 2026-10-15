-- migration:      0014
-- description:    drop organization domains table
-- author:         Platform Architecture Team
-- date:           2026-09-15
-- depends_on:     0013
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert organization domains table

DROP TABLE IF EXISTS auth_organization_domains CASCADE;

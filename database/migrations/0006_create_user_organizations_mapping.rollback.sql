-- migration:      0006
-- description:    drop user organizations mapping table
-- author:         Platform Architecture Team
-- date:           2026-08-19
-- depends_on:     0005
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert user organizations mapping table

DROP INDEX IF EXISTS idx_auth_user_orgs_user;
DROP INDEX IF EXISTS idx_auth_user_orgs_org;
DROP TABLE IF EXISTS auth_user_organizations;

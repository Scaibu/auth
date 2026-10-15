-- rollback:       0014
-- description:    drop auth_organization_domains table
-- author:         engineering
-- date:           2026-10-15

DROP TABLE IF EXISTS auth_organization_domains CASCADE;

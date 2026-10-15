-- migration:      0018
-- description:    drop auth scim tables
-- author:         Platform Architecture Team
-- date:           2026-09-25
-- depends_on:     0017
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert auth scim tables

DROP TABLE IF EXISTS auth_group_members CASCADE;
DROP TABLE IF EXISTS auth_groups CASCADE;
DROP TABLE IF EXISTS auth_scim_external_mappings CASCADE;
DROP TABLE IF EXISTS auth_scim_tokens CASCADE;

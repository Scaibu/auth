-- migration:      0025
-- description:    rollback passwordless auth magic links table and triggers
-- author:         Platform Architecture & Security Team
-- date:           2026-10-15
-- depends_on:     0024_create_auth_custom_roles_and_bitmasks.sql
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         clean rollback for ADR 0031

DROP TRIGGER IF EXISTS trg_auth_magic_links_immutability ON auth_magic_links;
DROP FUNCTION IF EXISTS fn_auth_magic_links_immutability_guard();
DROP TABLE IF EXISTS auth_magic_links;

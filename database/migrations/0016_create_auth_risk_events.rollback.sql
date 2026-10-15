-- migration:      0016
-- description:    drop auth risk events table
-- author:         Platform Architecture Team
-- date:           2026-09-20
-- depends_on:     0015
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert auth risk events table

DROP TABLE IF EXISTS auth_login_history CASCADE;

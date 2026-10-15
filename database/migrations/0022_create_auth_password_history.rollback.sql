-- migration:      0022
-- description:    drop auth password history table
-- author:         Platform Architecture Team
-- date:           2026-10-15
-- depends_on:     0021
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert auth password history table

DROP TABLE IF EXISTS auth_password_history CASCADE;

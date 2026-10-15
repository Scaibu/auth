-- migration:      0012
-- description:    remove session family composite indexes
-- author:         Platform Architecture Team
-- date:           2026-09-05
-- depends_on:     0011
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert session family composite indexes

DROP INDEX IF EXISTS idx_refresh_tokens_user_family_active;
DROP INDEX IF EXISTS idx_refresh_tokens_family_active;
DROP INDEX IF EXISTS idx_refresh_families_user_active;

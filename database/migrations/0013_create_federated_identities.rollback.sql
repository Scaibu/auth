-- migration:      0013
-- description:    drop federated identities table
-- author:         Platform Architecture Team
-- date:           2026-09-10
-- depends_on:     0012
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert federated identities table

DROP TABLE IF EXISTS auth_federated_identities CASCADE;

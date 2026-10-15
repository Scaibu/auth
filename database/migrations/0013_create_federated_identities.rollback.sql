-- migration:      0013_rollback
-- description:    drop auth_federated_identities table
-- author:         engineering
-- date:           2026-10-15
-- depends_on:     0013
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only

DROP TABLE IF EXISTS auth_federated_identities CASCADE;

-- migration:      0020
-- description:    drop auth saml tables
-- author:         Platform Architecture Team
-- date:           2026-10-02
-- depends_on:     0019
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert auth saml tables

DROP TABLE IF EXISTS auth_saml_assertion_replay CASCADE;
DROP TABLE IF EXISTS auth_saml_requests CASCADE;
DROP TABLE IF EXISTS auth_saml_providers CASCADE;

-- migration:      0001
-- description:    drop auth tables for multi-tenant organizations users api keys audit logs password resets
-- author:         Platform Architecture Team
-- date:           2026-08-16
-- depends_on:     none
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert initial auth schema setup

DROP POLICY IF EXISTS rls_auth_audit_logs_tenant_isolation ON auth_audit_logs;
DROP POLICY IF EXISTS rls_auth_api_keys_tenant_isolation ON auth_api_keys;
DROP POLICY IF EXISTS rls_auth_users_tenant_isolation ON auth_users;

DROP TABLE IF EXISTS auth_password_resets;
DROP TABLE IF EXISTS auth_audit_logs;
DROP TABLE IF EXISTS auth_api_keys;
DROP TABLE IF EXISTS auth_users;
DROP TABLE IF EXISTS auth_organizations;

-- Migration 0037 Rollback: Revert RLS enforcement and non-superuser application role
-- Reversible: YES

DROP POLICY IF EXISTS rls_auth_honeytokens_tenant_isolation ON auth_honeytokens;
ALTER TABLE auth_honeytokens NO FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_honeytokens DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_auth_break_glass_sessions_tenant_isolation ON auth_break_glass_sessions;
ALTER TABLE auth_break_glass_sessions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_break_glass_sessions DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_auth_user_encryption_keys_tenant_isolation ON auth_user_encryption_keys;
ALTER TABLE auth_user_encryption_keys NO FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_user_encryption_keys DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_auth_webhook_deliveries_tenant_isolation ON auth_webhook_deliveries;
ALTER TABLE auth_webhook_deliveries NO FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_webhook_deliveries DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_auth_webhook_subscriptions_tenant_isolation ON auth_webhook_subscriptions;
ALTER TABLE auth_webhook_subscriptions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_webhook_subscriptions DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_auth_role_audit_logs_tenant_isolation ON auth_role_audit_logs;
ALTER TABLE auth_role_audit_logs NO FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_role_audit_logs DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_auth_user_custom_roles_tenant_isolation ON auth_user_custom_roles;
ALTER TABLE auth_user_custom_roles NO FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_user_custom_roles DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_auth_custom_roles_tenant_isolation ON auth_custom_roles;
ALTER TABLE auth_custom_roles NO FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_custom_roles DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_auth_passkey_credentials_tenant_isolation ON auth_passkey_credentials;
ALTER TABLE auth_passkey_credentials NO FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_passkey_credentials DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_auth_oauth_codes_tenant_isolation ON auth_oauth_codes;
ALTER TABLE auth_oauth_codes NO FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_oauth_codes DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_auth_oauth_clients_tenant_isolation ON auth_oauth_clients;
ALTER TABLE auth_oauth_clients NO FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_oauth_clients DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_auth_relation_tuples_tenant_isolation ON auth_relation_tuples;
ALTER TABLE auth_relation_tuples NO FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_relation_tuples DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_auth_organization_domains_tenant_isolation ON auth_organization_domains;
ALTER TABLE auth_organization_domains NO FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_organization_domains DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_auth_user_organizations_tenant_isolation ON auth_user_organizations;
ALTER TABLE auth_user_organizations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_user_organizations DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_auth_audit_logs_tenant_isolation ON auth_audit_logs;
ALTER TABLE auth_audit_logs NO FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_audit_logs DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_auth_api_keys_tenant_isolation ON auth_api_keys;
ALTER TABLE auth_api_keys NO FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_api_keys DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_auth_users_tenant_isolation ON auth_users;
CREATE POLICY rls_auth_users_tenant_isolation ON auth_users
  FOR ALL
  USING (org_id = current_setting('app.current_org_id', true));
ALTER TABLE auth_users NO FORCE ROW LEVEL SECURITY;

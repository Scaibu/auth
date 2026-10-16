-- Migration 0037: Enforce Row Level Security with Non-Superuser Application Role
-- Mandated by: P0 Security & Blast Radius Checklist (Item 1)
-- Reversible: YES
-- Creates non-superuser role auth_app, enables & forces RLS across all tenant tables,
-- and establishes tenant isolation policies matching app.current_tenant_id or app.current_org_id.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth_app') THEN
    CREATE ROLE auth_app WITH LOGIN PASSWORD 'auth_app_secret_pass' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  ELSE
    ALTER ROLE auth_app WITH NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;

GRANT CONNECT ON DATABASE llm_observability TO auth_app;
GRANT USAGE ON SCHEMA public TO auth_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO auth_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO auth_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO auth_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO auth_app;

-- Enable and force RLS on all tenant-isolated tables
ALTER TABLE auth_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_users FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_auth_users_tenant_isolation ON auth_users;
CREATE POLICY rls_auth_users_tenant_isolation ON auth_users
  FOR ALL
  USING (org_id = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.current_org_id', true), '')));

ALTER TABLE auth_api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_api_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_auth_api_keys_tenant_isolation ON auth_api_keys;
CREATE POLICY rls_auth_api_keys_tenant_isolation ON auth_api_keys
  FOR ALL
  USING (org_id = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.current_org_id', true), '')));

ALTER TABLE auth_audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_audit_logs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_auth_audit_logs_tenant_isolation ON auth_audit_logs;
CREATE POLICY rls_auth_audit_logs_tenant_isolation ON auth_audit_logs
  FOR ALL
  USING (org_id = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.current_org_id', true), '')));

ALTER TABLE auth_user_organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_user_organizations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_auth_user_organizations_tenant_isolation ON auth_user_organizations;
CREATE POLICY rls_auth_user_organizations_tenant_isolation ON auth_user_organizations
  FOR ALL
  USING (org_id = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.current_org_id', true), '')));

ALTER TABLE auth_organization_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_organization_domains FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_auth_organization_domains_tenant_isolation ON auth_organization_domains;
CREATE POLICY rls_auth_organization_domains_tenant_isolation ON auth_organization_domains
  FOR ALL
  USING (org_id = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.current_org_id', true), '')));

ALTER TABLE auth_relation_tuples ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_relation_tuples FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_auth_relation_tuples_tenant_isolation ON auth_relation_tuples;
CREATE POLICY rls_auth_relation_tuples_tenant_isolation ON auth_relation_tuples
  FOR ALL
  USING (org_id = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.current_org_id', true), '')));

ALTER TABLE auth_oauth_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_oauth_clients FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_auth_oauth_clients_tenant_isolation ON auth_oauth_clients;
CREATE POLICY rls_auth_oauth_clients_tenant_isolation ON auth_oauth_clients
  FOR ALL
  USING (org_id = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.current_org_id', true), '')));

ALTER TABLE auth_oauth_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_oauth_codes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_auth_oauth_codes_tenant_isolation ON auth_oauth_codes;
CREATE POLICY rls_auth_oauth_codes_tenant_isolation ON auth_oauth_codes
  FOR ALL
  USING (org_id = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.current_org_id', true), '')));

ALTER TABLE auth_passkey_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_passkey_credentials FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_auth_passkey_credentials_tenant_isolation ON auth_passkey_credentials;
CREATE POLICY rls_auth_passkey_credentials_tenant_isolation ON auth_passkey_credentials
  FOR ALL
  USING (org_id = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.current_org_id', true), '')));

ALTER TABLE auth_custom_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_custom_roles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_auth_custom_roles_tenant_isolation ON auth_custom_roles;
CREATE POLICY rls_auth_custom_roles_tenant_isolation ON auth_custom_roles
  FOR ALL
  USING (org_id = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.current_org_id', true), '')));

ALTER TABLE auth_user_custom_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_user_custom_roles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_auth_user_custom_roles_tenant_isolation ON auth_user_custom_roles;
CREATE POLICY rls_auth_user_custom_roles_tenant_isolation ON auth_user_custom_roles
  FOR ALL
  USING (org_id = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.current_org_id', true), '')));

ALTER TABLE auth_role_audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_role_audit_logs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_auth_role_audit_logs_tenant_isolation ON auth_role_audit_logs;
CREATE POLICY rls_auth_role_audit_logs_tenant_isolation ON auth_role_audit_logs
  FOR ALL
  USING (org_id = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.current_org_id', true), '')));

ALTER TABLE auth_webhook_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_webhook_subscriptions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_auth_webhook_subscriptions_tenant_isolation ON auth_webhook_subscriptions;
CREATE POLICY rls_auth_webhook_subscriptions_tenant_isolation ON auth_webhook_subscriptions
  FOR ALL
  USING (org_id = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.current_org_id', true), '')));

ALTER TABLE auth_webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_webhook_deliveries FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_auth_webhook_deliveries_tenant_isolation ON auth_webhook_deliveries;
CREATE POLICY rls_auth_webhook_deliveries_tenant_isolation ON auth_webhook_deliveries
  FOR ALL
  USING (org_id = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.current_org_id', true), '')));

ALTER TABLE auth_user_encryption_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_user_encryption_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_auth_user_encryption_keys_tenant_isolation ON auth_user_encryption_keys;
CREATE POLICY rls_auth_user_encryption_keys_tenant_isolation ON auth_user_encryption_keys
  FOR ALL
  USING (org_id = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.current_org_id', true), '')));

ALTER TABLE auth_break_glass_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_break_glass_sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_auth_break_glass_sessions_tenant_isolation ON auth_break_glass_sessions;
CREATE POLICY rls_auth_break_glass_sessions_tenant_isolation ON auth_break_glass_sessions
  FOR ALL
  USING (org_id = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.current_org_id', true), '')));

ALTER TABLE auth_honeytokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_honeytokens FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_auth_honeytokens_tenant_isolation ON auth_honeytokens;
CREATE POLICY rls_auth_honeytokens_tenant_isolation ON auth_honeytokens
  FOR ALL
  USING (org_id = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.current_org_id', true), '')));

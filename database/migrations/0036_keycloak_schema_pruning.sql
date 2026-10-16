-- Migration 0036: Keycloak Schema Pruning & Technical Debt Reduction
-- Mandated by: ADR 0002 & TODO-KEYCLOAK Phase 4
-- Drops obsolete IAM tables superseded by Keycloak while strictly preserving application tenancy, policies, and audit logs.

DROP TABLE IF EXISTS auth_magic_links CASCADE;
DROP TABLE IF EXISTS auth_passkeys CASCADE;
DROP TABLE IF EXISTS auth_password_history CASCADE;
DROP TABLE IF EXISTS auth_password_resets CASCADE;
DROP TABLE IF EXISTS auth_refresh_tokens CASCADE;
DROP TABLE IF EXISTS auth_refresh_token_families CASCADE;
DROP TABLE IF EXISTS auth_recovery_codes CASCADE;
DROP TABLE IF EXISTS auth_mfa CASCADE;
DROP TABLE IF EXISTS auth_email_verifications CASCADE;
DROP TABLE IF EXISTS auth_token_denylist CASCADE;
DROP TABLE IF EXISTS auth_federated_identities CASCADE;
DROP TABLE IF EXISTS auth_scim_tokens CASCADE;
DROP TABLE IF EXISTS auth_scim_external_mappings CASCADE;
DROP TABLE IF EXISTS auth_group_members CASCADE;
DROP TABLE IF EXISTS auth_groups CASCADE;
DROP TABLE IF EXISTS auth_oidc_codes CASCADE;
DROP TABLE IF EXISTS auth_oidc_clients CASCADE;
DROP TABLE IF EXISTS auth_saml_requests CASCADE;
DROP TABLE IF EXISTS auth_saml_assertion_replay CASCADE;
DROP TABLE IF EXISTS auth_saml_providers CASCADE;

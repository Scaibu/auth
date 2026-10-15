-- Rollback: 0019_create_auth_oidc_tables.rollback.sql

DROP TABLE IF EXISTS auth_signing_keys CASCADE;
DROP TABLE IF EXISTS auth_oauth_codes CASCADE;
DROP TABLE IF EXISTS auth_oauth_clients CASCADE;

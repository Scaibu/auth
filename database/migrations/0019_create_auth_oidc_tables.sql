-- migration:      0019
-- description:    create auth oidc tables for oauth2 authorization server and pkce
-- author:         Platform Architecture Team
-- date:           2026-09-28
-- depends_on:     0018
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         support oauth2 authorization server clients codes and signing keys

CREATE TABLE IF NOT EXISTS auth_oauth_clients (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES auth_organizations(id) ON DELETE CASCADE,
    client_name VARCHAR(255) NOT NULL,
    client_secret_hash VARCHAR(255) NULL,
    redirect_uris JSONB NOT NULL DEFAULT '[]'::jsonb,
    grant_types JSONB NOT NULL DEFAULT '["authorization_code"]'::jsonb,
    response_types JSONB NOT NULL DEFAULT '["code"]'::jsonb,
    client_type VARCHAR(32) NOT NULL DEFAULT 'public',
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at_ms BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,

    CONSTRAINT auth_oauth_clients_type_ck CHECK (client_type IN ('public', 'confidential')),
    CONSTRAINT auth_oauth_clients_status_ck CHECK (status IN ('ACTIVE', 'SUSPENDED')),
    CONSTRAINT auth_oauth_clients_uris_ck CHECK (jsonb_typeof(redirect_uris) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_auth_oauth_clients_org 
    ON auth_oauth_clients(org_id) WHERE deleted_at IS NULL AND status = 'ACTIVE';

CREATE TABLE IF NOT EXISTS auth_oauth_codes (
    code VARCHAR(128) PRIMARY KEY,
    client_id VARCHAR(64) NOT NULL REFERENCES auth_oauth_clients(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    org_id VARCHAR(64) NOT NULL REFERENCES auth_organizations(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    code_challenge VARCHAR(128) NOT NULL,
    code_challenge_method VARCHAR(32) NOT NULL DEFAULT 'S256',
    scope VARCHAR(255) NOT NULL DEFAULT 'openid profile email',
    used BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at_ms BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL,

    CONSTRAINT auth_oauth_codes_method_ck CHECK (code_challenge_method = 'S256')
);

CREATE INDEX IF NOT EXISTS idx_auth_oauth_codes_client 
    ON auth_oauth_codes(client_id, expires_at_ms) WHERE used = FALSE;

CREATE TABLE IF NOT EXISTS auth_signing_keys (
    kid VARCHAR(64) PRIMARY KEY,
    kty VARCHAR(32) NOT NULL DEFAULT 'RSA',
    alg VARCHAR(32) NOT NULL DEFAULT 'RS256',
    use VARCHAR(32) NOT NULL DEFAULT 'sig',
    public_key_pem TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at_ms BIGINT NOT NULL,

    CONSTRAINT auth_signing_keys_status_ck CHECK (status IN ('ACTIVE', 'RETIRED'))
);

CREATE TABLE IF NOT EXISTS auth_saml_providers (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES auth_organizations(id) ON DELETE CASCADE,
    idp_entity_id VARCHAR(255) NOT NULL,
    idp_sso_url TEXT NOT NULL,
    idp_certificate_pem TEXT NOT NULL,
    sp_entity_id VARCHAR(255) NOT NULL,
    attribute_mapping JSONB NOT NULL DEFAULT '{"email":"email","name":"name"}'::jsonb,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at_ms BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,

    CONSTRAINT auth_saml_providers_status_ck CHECK (status IN ('ACTIVE', 'SUSPENDED')),
    CONSTRAINT auth_saml_providers_mapping_ck CHECK (jsonb_typeof(attribute_mapping) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_auth_saml_providers_org 
    ON auth_saml_providers(org_id) WHERE deleted_at IS NULL AND status = 'ACTIVE';

CREATE TABLE IF NOT EXISTS auth_saml_requests (
    relay_state VARCHAR(128) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES auth_organizations(id) ON DELETE CASCADE,
    provider_id VARCHAR(64) NOT NULL REFERENCES auth_saml_providers(id) ON DELETE CASCADE,
    request_id VARCHAR(128) NOT NULL,
    return_url TEXT NULL,
    expires_at_ms BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_saml_requests_expires 
    ON auth_saml_requests(expires_at_ms);

CREATE TABLE IF NOT EXISTS auth_saml_assertion_replay (
    assertion_id VARCHAR(128) PRIMARY KEY,
    expires_at_ms BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_saml_replay_expires 
    ON auth_saml_assertion_replay(expires_at_ms);

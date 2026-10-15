-- migration:      0023
-- description:    create auth passkey credentials table for webauthn fido2 authentication
-- author:         Platform Architecture Team
-- date:           2026-10-15
-- depends_on:     0022
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         support w3c webauthn level 3 phishing-resistant biometric & hardware passkeys

CREATE TABLE IF NOT EXISTS auth_passkey_credentials (
    id VARCHAR(64) PRIMARY KEY,
    credential_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    org_id VARCHAR(64) NOT NULL,
    public_key TEXT NOT NULL,
    counter BIGINT NOT NULL DEFAULT 0,
    device_type VARCHAR(32) NOT NULL DEFAULT 'single_device',
    backed_up BOOLEAN NOT NULL DEFAULT FALSE,
    transports JSONB NOT NULL DEFAULT '[]'::jsonb,
    aaguid VARCHAR(64) NULL,
    friendly_name VARCHAR(128) NOT NULL DEFAULT 'Passkey',
    created_at_ms BIGINT NOT NULL,
    last_used_at_ms BIGINT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,

    CONSTRAINT fk_auth_passkeys_user FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE,
    CONSTRAINT fk_auth_passkeys_org FOREIGN KEY (org_id) REFERENCES auth_organizations(id) ON DELETE CASCADE,
    CONSTRAINT uq_auth_passkeys_credential_id UNIQUE (credential_id)
);

CREATE INDEX IF NOT EXISTS idx_auth_passkeys_user_id 
    ON auth_passkey_credentials(user_id) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_auth_passkeys_org_id 
    ON auth_passkey_credentials(org_id) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_auth_passkeys_cred_lookup 
    ON auth_passkey_credentials(credential_id) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS auth_passkey_challenges (
    challenge_id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NULL,
    challenge VARCHAR(255) NOT NULL,
    origin VARCHAR(255) NOT NULL,
    rp_id VARCHAR(255) NOT NULL,
    challenge_type VARCHAR(32) NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_auth_passkey_challenges_lookup 
    ON auth_passkey_challenges(challenge_id, expires_at_ms);

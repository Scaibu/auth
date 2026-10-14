-- Migration: 0010_create_refresh_tokens_and_families.sql
-- Description: RFC 6749 §10.4 Refresh Token Rotation & Family Reuse Detection Schema

CREATE TABLE IF NOT EXISTS auth_refresh_token_families (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    created_at_ms BIGINT NOT NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_reason VARCHAR(255),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_auth_refresh_families_user_id ON auth_refresh_token_families(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_refresh_families_revoked ON auth_refresh_token_families(is_revoked);

CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
    token_id VARCHAR(64) PRIMARY KEY,
    family_id VARCHAR(64) NOT NULL REFERENCES auth_refresh_token_families(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    generation INT NOT NULL DEFAULT 1,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at_ms BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    consumed_at_ms BIGINT,
    created_ip VARCHAR(64),
    user_agent VARCHAR(512)
);

CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_hash ON auth_refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_family_id ON auth_refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_user_id ON auth_refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_expires_at ON auth_refresh_tokens(expires_at_ms);

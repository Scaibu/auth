-- migration:      0025
-- description:    create passwordless auth magic links with SHA-256 token hashing, single-use guards, and anti-scanner defense
-- author:         Platform Architecture & Security Team
-- date:           2026-10-15
-- depends_on:     0024_create_auth_custom_roles_and_bitmasks.sql
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         enterprise passwordless authentication with zero-trust token hashing and scanner bot defense (ADR 0031)
--
-- Documented Nullable Columns:
--   - redirect_url: Optional destination URL; defaults to dashboard if omitted by client.
--   - request_ip: May be unavailable if client connects over direct Unix domain socket or local test harness.
--   - user_agent_hash: Optional client fingerprint; omitted when User-Agent header is missing or client is CLI.
--   - consumed_at_ms: NULL until single-use atomic consumption occurs.
--   - consumed_ip: NULL until link is redeemed.
--   - superseded_at_ms: NULL until a newer magic link invalidates this active token.
--   - deleted_at: NULL while record is active; populated on GDPR retention cascade soft-deletion.

CREATE TABLE IF NOT EXISTS auth_magic_links (
    id VARCHAR(64) PRIMARY KEY,
    public_id VARCHAR(64) NOT NULL UNIQUE,
    org_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    email VARCHAR(255) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    redirect_url VARCHAR(512) DEFAULT NULL,
    request_ip VARCHAR(45) DEFAULT NULL,
    user_agent_hash VARCHAR(64) DEFAULT NULL,
    consumed_at_ms BIGINT DEFAULT NULL,
    consumed_ip VARCHAR(45) DEFAULT NULL,
    superseded_at_ms BIGINT DEFAULT NULL,
    version BIGINT NOT NULL DEFAULT 1,
    expires_at_ms BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,

    CONSTRAINT auth_magic_links_org_fk FOREIGN KEY (org_id)
        REFERENCES auth_organizations(id) ON DELETE CASCADE,
    CONSTRAINT auth_magic_links_user_fk FOREIGN KEY (user_id)
        REFERENCES auth_users(id) ON DELETE CASCADE,
    CONSTRAINT auth_magic_links_email_ck CHECK (email = LOWER(TRIM(email)) AND LENGTH(email) >= 3),
    CONSTRAINT auth_magic_links_hash_len_ck CHECK (LENGTH(token_hash) = 64),
    CONSTRAINT auth_magic_links_expiry_ck CHECK (expires_at_ms > created_at_ms),
    CONSTRAINT auth_magic_links_version_ck CHECK (version >= 1),
    CONSTRAINT auth_magic_links_org_id_uniq UNIQUE (org_id, id)
);

CREATE INDEX IF NOT EXISTS idx_auth_magic_links_token_hash_active
    ON auth_magic_links (token_hash)
    WHERE consumed_at_ms IS NULL AND superseded_at_ms IS NULL AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_auth_magic_links_user_active
    ON auth_magic_links (org_id, user_id, created_at_ms DESC)
    WHERE consumed_at_ms IS NULL AND superseded_at_ms IS NULL AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_auth_magic_links_email_rate_limit
    ON auth_magic_links (email, created_at_ms DESC)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_auth_magic_links_ip_rate_limit
    ON auth_magic_links (request_ip, created_at_ms DESC)
    WHERE request_ip IS NOT NULL AND deleted_at IS NULL;

CREATE OR REPLACE FUNCTION fn_auth_magic_links_immutability_guard()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.consumed_at_ms IS NOT NULL AND (NEW.consumed_at_ms <> OLD.consumed_at_ms OR NEW.token_hash <> OLD.token_hash) THEN
        RAISE EXCEPTION 'Consumed magic link tokens are cryptographically locked and immutable';
    END IF;
    IF OLD.token_hash <> NEW.token_hash THEN
        RAISE EXCEPTION 'Token hash is immutable once generated';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_auth_magic_links_immutability ON auth_magic_links;
CREATE TRIGGER trg_auth_magic_links_immutability
    BEFORE UPDATE ON auth_magic_links
    FOR EACH ROW
    EXECUTE FUNCTION fn_auth_magic_links_immutability_guard();

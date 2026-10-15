-- Migration: 0026_create_auth_webhook_subscriptions
-- Description: Creates auth_webhook_subscriptions and auth_webhook_deliveries tables with HMAC signing metadata and anti-replay nonces
-- Invariants: Strict compliance with 05-db-writing-rules.md (surrogate UUIDv7 id, external public_id, composite tenant keys, versioning)

CREATE TABLE IF NOT EXISTS auth_webhook_subscriptions (
    id VARCHAR(64) PRIMARY KEY,
    public_id VARCHAR(64) NOT NULL,
    org_id VARCHAR(64) NOT NULL,
    target_url VARCHAR(512) NOT NULL,
    secret_hash VARCHAR(128) NOT NULL,
    secret_prefix VARCHAR(64) NOT NULL,
    subscribed_events JSONB NOT NULL DEFAULT '["*"]'::jsonb,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    version BIGINT NOT NULL DEFAULT 1,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    deleted_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_auth_webhook_subs_org
        FOREIGN KEY (org_id)
        REFERENCES auth_organizations(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_auth_webhook_subs_public_id
        UNIQUE (public_id),

    CONSTRAINT uq_auth_webhook_subs_org_composite
        UNIQUE (org_id, id),

    CONSTRAINT chk_auth_webhook_subs_url_format
        CHECK (target_url ~* '^https?://[^\s/$.?#].[^\s]*$')
);

CREATE INDEX IF NOT EXISTS idx_auth_webhook_subs_org_active
    ON auth_webhook_subscriptions(org_id, active)
    WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS auth_webhook_deliveries (
    id VARCHAR(64) PRIMARY KEY,
    public_id VARCHAR(64) NOT NULL,
    subscription_id VARCHAR(64) NOT NULL,
    org_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    nonce VARCHAR(64) NOT NULL,
    response_status INT NOT NULL,
    execution_duration_ms BIGINT NOT NULL,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(512) NULL,
    delivered_at_ms BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_auth_webhook_deliv_sub
        FOREIGN KEY (subscription_id)
        REFERENCES auth_webhook_subscriptions(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_auth_webhook_deliv_org
        FOREIGN KEY (org_id)
        REFERENCES auth_organizations(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_auth_webhook_deliv_public_id
        UNIQUE (public_id),

    CONSTRAINT uq_auth_webhook_deliv_nonce
        UNIQUE (nonce)
);

CREATE INDEX IF NOT EXISTS idx_auth_webhook_deliv_sub_delivered
    ON auth_webhook_deliveries(subscription_id, delivered_at_ms DESC);

CREATE INDEX IF NOT EXISTS idx_auth_webhook_deliv_org_success
    ON auth_webhook_deliveries(org_id, success, delivered_at_ms DESC);

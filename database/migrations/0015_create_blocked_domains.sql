-- migration:      0015
-- description:    create blocked domains table for disposable email prevention
-- author:         Platform Architecture Team
-- date:           2026-09-18
-- depends_on:     0014
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         block disposable and fraudulent email providers from registering

-- ADR 0021 Extensible Domain Protection Specification

CREATE TABLE IF NOT EXISTS auth_blocked_domains (
    domain_name VARCHAR(255) PRIMARY KEY,
    category VARCHAR(64) NOT NULL DEFAULT 'FREEMAIL',
    reason TEXT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_auth_blocked_domains_category ON auth_blocked_domains(category);

-- Seed canonical dynamic freemail and disposable providers
INSERT INTO auth_blocked_domains (domain_name, category, reason, created_at_ms, updated_at_ms)
VALUES
    ('gmail.com', 'FREEMAIL', 'Canonical public freemail provider', 1700000000000, 1700000000000),
    ('googlemail.com', 'FREEMAIL', 'Canonical public freemail provider', 1700000000000, 1700000000000),
    ('yahoo.com', 'FREEMAIL', 'Canonical public freemail provider', 1700000000000, 1700000000000),
    ('hotmail.com', 'FREEMAIL', 'Canonical public freemail provider', 1700000000000, 1700000000000),
    ('outlook.com', 'FREEMAIL', 'Canonical public freemail provider', 1700000000000, 1700000000000),
    ('icloud.com', 'FREEMAIL', 'Canonical public freemail provider', 1700000000000, 1700000000000),
    ('proton.me', 'FREEMAIL', 'Canonical public freemail provider', 1700000000000, 1700000000000),
    ('protonmail.com', 'FREEMAIL', 'Canonical public freemail provider', 1700000000000, 1700000000000),
    ('aol.com', 'FREEMAIL', 'Canonical public freemail provider', 1700000000000, 1700000000000),
    ('mail.com', 'FREEMAIL', 'Canonical public freemail provider', 1700000000000, 1700000000000),
    ('zoho.com', 'FREEMAIL', 'Canonical public freemail provider', 1700000000000, 1700000000000),
    ('yandex.com', 'FREEMAIL', 'Canonical public freemail provider', 1700000000000, 1700000000000)
ON CONFLICT (domain_name) DO NOTHING;

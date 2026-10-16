-- migration:      0028
-- description:    add field level envelope encryption columns, blind index, and integrity check constraints to auth users
-- author:         Platform Architecture & Security Team
-- date:           2026-10-16
-- depends_on:     0027_add_m2m_client_credentials.sql
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         nist sp 800-38d field level envelope encryption and blind indexing for gdpr pii defense (ADR 0035)

ALTER TABLE auth_users
    ADD COLUMN IF NOT EXISTS name_encrypted TEXT NULL,
    ADD COLUMN IF NOT EXISTS email_encrypted TEXT NULL,
    ADD COLUMN IF NOT EXISTS email_blind_index VARCHAR(64) NULL,
    ADD COLUMN IF NOT EXISTS mfa_secret_encrypted TEXT NULL;

-- 1. Bounded & Normalized Length Constraints
ALTER TABLE auth_users
    ADD CONSTRAINT auth_users_name_enc_trimmed_ck 
        CHECK (name_encrypted IS NULL OR (name_encrypted = btrim(name_encrypted) AND name_encrypted <> '')),
    ADD CONSTRAINT auth_users_email_enc_trimmed_ck 
        CHECK (email_encrypted IS NULL OR (email_encrypted = btrim(email_encrypted) AND email_encrypted <> '')),
    ADD CONSTRAINT auth_users_email_blind_index_format_ck 
        CHECK (email_blind_index IS NULL OR (email_blind_index ~ '^[a-f0-9]{64}$')),
    ADD CONSTRAINT auth_users_mfa_secret_enc_trimmed_ck 
        CHECK (mfa_secret_encrypted IS NULL OR (mfa_secret_encrypted = btrim(mfa_secret_encrypted) AND mfa_secret_encrypted <> ''));

-- 2. Envelope Format Prefix Verification ('enc:v1:...')
ALTER TABLE auth_users
    ADD CONSTRAINT auth_users_name_enc_prefix_ck 
        CHECK (name_encrypted IS NULL OR name_encrypted LIKE 'enc:v1:%'),
    ADD CONSTRAINT auth_users_email_enc_prefix_ck 
        CHECK (email_encrypted IS NULL OR email_encrypted LIKE 'enc:v1:%'),
    ADD CONSTRAINT auth_users_mfa_secret_enc_prefix_ck 
        CHECK (mfa_secret_encrypted IS NULL OR mfa_secret_encrypted LIKE 'enc:v1:%');

-- 3. Blind Index Fast Lookup Index
CREATE INDEX IF NOT EXISTS idx_auth_users_email_blind_index 
    ON auth_users(email_blind_index) 
    WHERE email_blind_index IS NOT NULL;

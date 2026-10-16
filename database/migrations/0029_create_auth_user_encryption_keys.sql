-- migration:      0029
-- description:    create auth_user_encryption_keys table for user DEK registry and GDPR Article 17 cryptographic shredding
-- author:         Platform Architecture & Security Team
-- date:           2026-10-16
-- depends_on:     0028_add_field_level_encryption.sql
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         GDPR Article 17 cryptographic erasure and NIST SP 800-88 compliance via user DEK registry (ADR 0036)

CREATE TABLE IF NOT EXISTS auth_user_encryption_keys (
    id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    org_id VARCHAR(64) NOT NULL,
    kid VARCHAR(64) NOT NULL,
    encrypted_dek TEXT NOT NULL,
    dek_status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE',
    version BIGINT NOT NULL DEFAULT 1,
    shredded_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT auth_user_keys_pk PRIMARY KEY (id),
    CONSTRAINT auth_user_keys_user_id_uk UNIQUE (user_id),
    CONSTRAINT auth_user_keys_user_id_fk FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE,
    CONSTRAINT auth_user_keys_status_ck CHECK (dek_status IN ('ACTIVE', 'SHREDDED')),
    CONSTRAINT auth_user_keys_dek_trimmed_ck CHECK (encrypted_dek = btrim(encrypted_dek) AND encrypted_dek <> ''),
    CONSTRAINT auth_user_keys_dek_prefix_ck CHECK (encrypted_dek LIKE 'enc:v1:%'),
    CONSTRAINT auth_user_keys_shred_state_ck CHECK (
        (dek_status = 'ACTIVE' AND shredded_at IS NULL) OR
        (dek_status = 'SHREDDED' AND shredded_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_auth_user_keys_user_id ON auth_user_encryption_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_user_keys_org_id ON auth_user_encryption_keys(org_id);
CREATE INDEX IF NOT EXISTS idx_auth_user_keys_status ON auth_user_encryption_keys(dek_status);

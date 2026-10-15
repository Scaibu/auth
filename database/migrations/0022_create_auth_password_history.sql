-- migration:      0022
-- description:    create auth password history table for cyclic reuse prevention
-- author:         Platform Architecture Team
-- date:           2026-10-15
-- depends_on:     0021
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         enforce nist sp 800-63b password history to prevent credential recycling

CREATE TABLE IF NOT EXISTS auth_password_history (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    created_at_ms BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL,

    CONSTRAINT fk_auth_password_history_user FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_auth_password_history_user_id 
    ON auth_password_history(user_id) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_auth_password_history_user_created 
    ON auth_password_history(user_id, created_at_ms DESC) WHERE deleted_at IS NULL;

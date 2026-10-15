-- migration:      0009
-- description:    create mfa and recovery codes tables for totp authentication
-- author:         Platform Architecture Team
-- date:           2026-08-25
-- depends_on:     0008
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         store hashed totp secrets and single-use emergency recovery codes

ALTER TABLE auth_users
  ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(255) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS mfa_enrolled_at_ms BIGINT DEFAULT NULL;

CREATE TABLE IF NOT EXISTS auth_recovery_codes (
  id            VARCHAR(128) PRIMARY KEY,
  user_id       VARCHAR(128) NOT NULL,
  code_hash     VARCHAR(512) NOT NULL,
  used          BOOLEAN      NOT NULL DEFAULT FALSE,
  created_at_ms BIGINT       NOT NULL,
  used_at_ms    BIGINT       DEFAULT NULL,
  created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  deleted_at    TIMESTAMP    DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_recovery_codes_user_id
  ON auth_recovery_codes (user_id)
  WHERE deleted_at IS NULL AND used = FALSE;

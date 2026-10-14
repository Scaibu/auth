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

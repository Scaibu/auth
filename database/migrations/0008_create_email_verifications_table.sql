-- migration:      0008
-- description:    create email verifications table for email confirmation flows
-- author:         Platform Architecture Team
-- date:           2026-08-22
-- depends_on:     0007
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         secure email address verification tokens with expiry for user registration

ALTER TABLE auth_users
  ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS auth_email_verifications (
  token_hash    VARCHAR(512) PRIMARY KEY,
  user_id       VARCHAR(128) NOT NULL,
  email         VARCHAR(255) NOT NULL,
  expires_at_ms BIGINT       NOT NULL,
  used          BOOLEAN      NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  deleted_at    TIMESTAMP    DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_email_verifications_user_id
  ON auth_email_verifications (user_id)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_auth_email_verifications_email
  ON auth_email_verifications (email)
  WHERE deleted_at IS NULL;

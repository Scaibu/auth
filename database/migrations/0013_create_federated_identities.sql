-- migration:      0013
-- description:    create federated identities table for oauth2 and oidc single sign on
-- author:         engineering
-- date:           2026-10-15
-- depends_on:     0012
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         support google and github federated single sign on and account linking

CREATE TABLE IF NOT EXISTS auth_federated_identities (
  id VARCHAR(64) PRIMARY KEY,
  user_id VARCHAR(64) NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  provider VARCHAR(32) NOT NULL,
  provider_subject_id VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  created_at_ms BIGINT NOT NULL,
  updated_at_ms BIGINT NOT NULL,
  CONSTRAINT uq_auth_fed_provider_subject UNIQUE (provider, provider_subject_id),
  CONSTRAINT uq_auth_fed_user_provider UNIQUE (user_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_auth_fed_user_id ON auth_federated_identities(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_fed_email ON auth_federated_identities(email);

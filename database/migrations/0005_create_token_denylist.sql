-- migration:      0005
-- description:    create token denylist table for revoked jwt tokens
-- author:         Platform Architecture Team
-- date:           2026-08-18
-- depends_on:     0004
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         enable immediate jwt revocation and token blacklisting across distributed services

CREATE TABLE IF NOT EXISTS auth_token_denylist (
  token_hash VARCHAR(512) PRIMARY KEY,
  expires_at_ms BIGINT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_auth_token_denylist_exp ON auth_token_denylist(expires_at_ms);

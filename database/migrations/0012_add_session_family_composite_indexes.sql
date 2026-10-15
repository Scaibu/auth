-- migration:      0012
-- description:    add session family composite indexes for high-throughput lookup
-- author:         Platform Architecture Team
-- date:           2026-09-05
-- depends_on:     0011
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         optimize session verification queries under high concurrency

CREATE INDEX IF NOT EXISTS idx_refresh_families_user_active 
ON auth_refresh_token_families(user_id, is_revoked);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_active 
ON auth_refresh_tokens(family_id, is_revoked, expires_at_ms);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_family_active 
ON auth_refresh_tokens(user_id, family_id, is_revoked);

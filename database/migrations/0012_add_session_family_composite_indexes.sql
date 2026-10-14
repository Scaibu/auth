-- Migration: 0012_add_session_family_composite_indexes.sql
-- Description: Composite and partial indexes for high-speed multi-device session enumeration and remote kill operations (OWASP ASVS 3.3)

CREATE INDEX IF NOT EXISTS idx_refresh_families_user_active 
ON auth_refresh_token_families(user_id, is_revoked);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_active 
ON auth_refresh_tokens(family_id, is_revoked, expires_at_ms);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_family_active 
ON auth_refresh_tokens(user_id, family_id, is_revoked);

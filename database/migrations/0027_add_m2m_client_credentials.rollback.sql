-- rollback:       0027
-- description:    rollback m2m client credentials columns on auth oauth clients
-- author:         Platform Architecture Team
-- date:           2026-10-16

DROP INDEX IF EXISTS idx_auth_oauth_clients_m2m;

ALTER TABLE auth_oauth_clients
    DROP COLUMN IF EXISTS token_ttl_seconds,
    DROP COLUMN IF EXISTS allowed_scopes,
    DROP COLUMN IF EXISTS secret_prefix;

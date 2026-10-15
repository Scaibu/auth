-- migration:      0027
-- description:    extend auth oauth clients for machine to machine client credentials grant
-- author:         Platform Architecture Team
-- date:           2026-10-16
-- depends_on:     0026
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         support rfc 6749 section 4.4 client credentials grant and granular workload scopes

ALTER TABLE auth_oauth_clients
    ADD COLUMN IF NOT EXISTS secret_prefix VARCHAR(32) NULL,
    ADD COLUMN IF NOT EXISTS allowed_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS token_ttl_seconds INTEGER NOT NULL DEFAULT 3600;

CREATE INDEX IF NOT EXISTS idx_auth_oauth_clients_m2m 
    ON auth_oauth_clients(id, org_id) 
    WHERE deleted_at IS NULL AND status = 'ACTIVE';

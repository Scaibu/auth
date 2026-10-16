-- migration:      0033
-- description:    extend auth_oauth_clients for mutual-tls client authentication and certificate-bound tokens
-- author:         Platform Architecture & Security Team
-- date:           2026-10-16
-- depends_on:     0032_create_auth_break_glass_sessions.sql
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         RFC 8705 OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens (ADR 0040)
-- nullable_columns:
--   - tls_client_auth_subject_dn: Subject DN or SAN for tls_client_auth PKI verification
--   - certificate_thumbprint: SHA-256 base64url thumbprint (43 chars) for self_signed_tls_client_auth pinned verification

ALTER TABLE auth_oauth_clients
    ADD COLUMN IF NOT EXISTS token_endpoint_auth_method VARCHAR(32) NOT NULL DEFAULT 'client_secret_post',
    ADD COLUMN IF NOT EXISTS tls_client_auth_subject_dn VARCHAR(255) NULL,
    ADD COLUMN IF NOT EXISTS certificate_thumbprint VARCHAR(64) NULL;

ALTER TABLE auth_oauth_clients DROP CONSTRAINT IF EXISTS auth_oauth_clients_auth_method_ck;
ALTER TABLE auth_oauth_clients ADD CONSTRAINT auth_oauth_clients_auth_method_ck
    CHECK (token_endpoint_auth_method IN (
        'client_secret_basic',
        'client_secret_post',
        'tls_client_auth',
        'self_signed_tls_client_auth',
        'none'
    ));

-- RFC 8705 §2: mTLS client authentication is only valid for confidential clients
ALTER TABLE auth_oauth_clients DROP CONSTRAINT IF EXISTS auth_oauth_clients_mtls_confidential_ck;
ALTER TABLE auth_oauth_clients ADD CONSTRAINT auth_oauth_clients_mtls_confidential_ck
    CHECK (
        token_endpoint_auth_method NOT IN ('tls_client_auth', 'self_signed_tls_client_auth')
        OR client_type = 'confidential'
    );

-- SHA-256 base64url thumbprint format verification (RFC 8705 Section 3)
ALTER TABLE auth_oauth_clients DROP CONSTRAINT IF EXISTS auth_oauth_clients_cert_thumbprint_ck;
ALTER TABLE auth_oauth_clients ADD CONSTRAINT auth_oauth_clients_cert_thumbprint_ck
    CHECK (certificate_thumbprint IS NULL OR certificate_thumbprint ~ '^[A-Za-z0-9_-]{43}$');

-- Subject DN must be non-empty, trimmed, and contain standard X.509 attribute markers
ALTER TABLE auth_oauth_clients DROP CONSTRAINT IF EXISTS auth_oauth_clients_subject_dn_ck;
ALTER TABLE auth_oauth_clients ADD CONSTRAINT auth_oauth_clients_subject_dn_ck
    CHECK (
        tls_client_auth_subject_dn IS NULL OR (
            length(btrim(tls_client_auth_subject_dn)) >= 3
            AND tls_client_auth_subject_dn ~ '(CN=|O=|OU=|DC=)'
        )
    );

-- Binding completeness and mutual exclusivity
ALTER TABLE auth_oauth_clients DROP CONSTRAINT IF EXISTS auth_oauth_clients_mtls_binding_ck;
ALTER TABLE auth_oauth_clients ADD CONSTRAINT auth_oauth_clients_mtls_binding_ck
    CHECK (
        (token_endpoint_auth_method NOT IN ('tls_client_auth', 'self_signed_tls_client_auth') 
            AND tls_client_auth_subject_dn IS NULL 
            AND certificate_thumbprint IS NULL)
        OR
        (token_endpoint_auth_method = 'tls_client_auth' 
            AND tls_client_auth_subject_dn IS NOT NULL 
            AND certificate_thumbprint IS NULL)
        OR
        (token_endpoint_auth_method = 'self_signed_tls_client_auth' 
            AND certificate_thumbprint IS NOT NULL 
            AND tls_client_auth_subject_dn IS NULL)
    );

-- Enforce global uniqueness of pinned certificate thumbprints among active clients to prevent cross-tenant identity hijacking
DROP INDEX IF EXISTS idx_auth_oauth_clients_cert_thumbprint;
CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_oauth_clients_cert_thumbprint
    ON auth_oauth_clients(certificate_thumbprint)
    WHERE deleted_at IS NULL AND certificate_thumbprint IS NOT NULL;

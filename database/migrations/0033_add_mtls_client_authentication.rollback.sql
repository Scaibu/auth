-- rollback:        0033
-- description:     revert migration 0033 auth_oauth_clients mtls additions
-- author:          Platform Architecture & Security Team
-- date:            2026-10-16
-- applies_to:      0033_add_mtls_client_authentication.sql
-- lock_risk:       LOW
-- rows_affected:   schema only
-- reason:          rollback RFC 8705 mTLS client auth columns

DROP INDEX IF EXISTS uq_auth_oauth_clients_cert_thumbprint;
DROP INDEX IF EXISTS idx_auth_oauth_clients_cert_thumbprint;

ALTER TABLE auth_oauth_clients DROP CONSTRAINT IF EXISTS auth_oauth_clients_mtls_binding_ck;
ALTER TABLE auth_oauth_clients DROP CONSTRAINT IF EXISTS auth_oauth_clients_subject_dn_ck;
ALTER TABLE auth_oauth_clients DROP CONSTRAINT IF EXISTS auth_oauth_clients_cert_thumbprint_ck;
ALTER TABLE auth_oauth_clients DROP CONSTRAINT IF EXISTS auth_oauth_clients_mtls_confidential_ck;
ALTER TABLE auth_oauth_clients DROP CONSTRAINT IF EXISTS auth_oauth_clients_auth_method_ck;

ALTER TABLE auth_oauth_clients
    DROP COLUMN IF EXISTS certificate_thumbprint,
    DROP COLUMN IF EXISTS tls_client_auth_subject_dn,
    DROP COLUMN IF EXISTS token_endpoint_auth_method;

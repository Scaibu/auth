-- rollback:       0028
-- description:    rollback field level envelope encryption columns, constraints, and indexes on auth users
-- author:         Platform Architecture & Security Team
-- date:           2026-10-16

DROP INDEX IF EXISTS idx_auth_users_email_blind_index;

ALTER TABLE auth_users
    DROP CONSTRAINT IF EXISTS auth_users_mfa_secret_enc_prefix_ck,
    DROP CONSTRAINT IF EXISTS auth_users_email_enc_prefix_ck,
    DROP CONSTRAINT IF EXISTS auth_users_name_enc_prefix_ck,
    DROP CONSTRAINT IF EXISTS auth_users_mfa_secret_enc_trimmed_ck,
    DROP CONSTRAINT IF EXISTS auth_users_email_blind_index_format_ck,
    DROP CONSTRAINT IF EXISTS auth_users_email_enc_trimmed_ck,
    DROP CONSTRAINT IF EXISTS auth_users_name_enc_trimmed_ck;

ALTER TABLE auth_users
    DROP COLUMN IF EXISTS mfa_secret_encrypted,
    DROP COLUMN IF EXISTS email_blind_index,
    DROP COLUMN IF EXISTS email_encrypted,
    DROP COLUMN IF EXISTS name_encrypted;

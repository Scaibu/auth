-- migration:      0032
-- description:    create auth_break_glass_sessions table for time-bound emergency access workflow
-- author:         Platform Architecture & Security Team
-- date:           2026-10-16
-- depends_on:     0031_upgrade_auth_signing_keys_eddsa.sql
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         SOC 2 CC6.1, CC6.2 and NIST SP 800-53 emergency access workflow with 4-hour hard ceiling (ADR 0039)
-- nullable_columns:
--   - terminated_at: epoch timestamp when session was terminated, null while active
--   - terminated_by: user id who terminated the session, null while active
--   - terminated_reason: operational justification for termination, null while active

CREATE TABLE IF NOT EXISTS auth_break_glass_sessions (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    incident_ticket_id VARCHAR(64) NOT NULL,
    justification TEXT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVATED',
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    elevated_role VARCHAR(32) NOT NULL DEFAULT 'super_admin',
    activated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    terminated_at TIMESTAMPTZ NULL,
    terminated_by VARCHAR(64) NULL,
    terminated_reason VARCHAR(255) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT auth_break_glass_org_id_fk FOREIGN KEY (org_id) REFERENCES auth_organizations(id) ON DELETE CASCADE,
    CONSTRAINT auth_break_glass_user_id_fk FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE,
    CONSTRAINT auth_break_glass_status_ck CHECK (status IN ('ACTIVATED', 'TERMINATED', 'EXPIRED')),
    CONSTRAINT auth_break_glass_duration_ck CHECK (
        expires_at > activated_at AND
        EXTRACT(EPOCH FROM (expires_at - activated_at)) <= 14400
    ),
    CONSTRAINT auth_break_glass_justification_ck CHECK (length(btrim(justification)) >= 10),
    CONSTRAINT auth_break_glass_ticket_ck CHECK (incident_ticket_id ~ '^[A-Z0-9_-]{3,64}$'),
    CONSTRAINT auth_break_glass_token_hash_ck CHECK (token_hash ~ '^[a-f0-9]{64}$'),
    CONSTRAINT auth_break_glass_termination_ck CHECK (
        (status != 'TERMINATED' AND terminated_at IS NULL AND terminated_by IS NULL AND terminated_reason IS NULL) OR
        (status = 'TERMINATED' AND terminated_at IS NOT NULL AND terminated_by IS NOT NULL AND terminated_reason IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_auth_break_glass_lookup ON auth_break_glass_sessions(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_break_glass_org ON auth_break_glass_sessions(org_id);

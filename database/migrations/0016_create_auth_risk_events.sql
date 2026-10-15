-- migration:      0016
-- description:    create auth risk events table for adaptive step-up authentication
-- author:         Platform Architecture Team
-- date:           2026-09-20
-- depends_on:     0015
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         log authentication risk signals ip velocity and anomalous locations

CREATE TABLE IF NOT EXISTS auth_login_history (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    ip_address VARCHAR(45) NOT NULL,
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    asn VARCHAR(64),
    is_datacenter BOOLEAN NOT NULL DEFAULT FALSE,
    device_fingerprint VARCHAR(64) NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0,
    created_at_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_login_history_user_time 
    ON auth_login_history(user_id, created_at_ms DESC);

CREATE INDEX IF NOT EXISTS idx_auth_login_history_ip
    ON auth_login_history(ip_address);

-- Migration: 0016_create_auth_risk_events.sql
-- Description: Creates auth_login_history table for adaptive risk-based authentication tracking

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

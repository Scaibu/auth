-- Migration Rollback: 0016_create_auth_risk_events.rollback.sql
-- Description: Drops auth_login_history table

DROP TABLE IF EXISTS auth_login_history CASCADE;

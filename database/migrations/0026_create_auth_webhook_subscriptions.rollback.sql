-- Rollback Migration: 0026_create_auth_webhook_subscriptions.rollback.sql
-- Description: Drops auth_webhook_deliveries and auth_webhook_subscriptions tables

DROP TABLE IF EXISTS auth_webhook_deliveries CASCADE;
DROP TABLE IF EXISTS auth_webhook_subscriptions CASCADE;

-- Rollback migration for 0038_create_auth_outbox_table.sql

DROP TABLE IF EXISTS auth_outbox CASCADE;

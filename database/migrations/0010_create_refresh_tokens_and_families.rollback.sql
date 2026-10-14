-- Rollback Migration: 0010_create_refresh_tokens_and_families.rollback.sql
DROP TABLE IF EXISTS auth_refresh_tokens;
DROP TABLE IF EXISTS auth_refresh_token_families;

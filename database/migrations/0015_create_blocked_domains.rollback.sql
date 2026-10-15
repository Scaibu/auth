-- Rollback Migration 0015: Drop Dynamic Blocked Domains Table
DROP TABLE IF EXISTS auth_blocked_domains CASCADE;

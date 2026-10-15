-- Rollback: 0018_create_auth_scim_tables.rollback.sql

DROP TABLE IF EXISTS auth_group_members CASCADE;
DROP TABLE IF EXISTS auth_groups CASCADE;
DROP TABLE IF EXISTS auth_scim_external_mappings CASCADE;
DROP TABLE IF EXISTS auth_scim_tokens CASCADE;

-- Rollback Migration: 0017_create_auth_policies_and_relations.rollback.sql
-- Description: Drops Zanzibar-style relationship tuples table and indexes

DROP TABLE IF EXISTS auth_relation_tuples CASCADE;

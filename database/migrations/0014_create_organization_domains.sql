-- migration:      0014
-- description:    create organization claimed domains table for dns txt verification and verified auto join
-- author:         engineering
-- date:           2026-10-15
-- depends_on:     0013
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         support enterprise domain claiming and verified auto-join per ADR 0021

CREATE TABLE IF NOT EXISTS auth_organization_domains (
  id VARCHAR(64) PRIMARY KEY,
  org_id VARCHAR(64) NOT NULL REFERENCES auth_organizations(id) ON DELETE CASCADE,
  domain_name VARCHAR(255) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'PENDING_VERIFICATION',
  verification_token VARCHAR(255) NOT NULL,
  verification_method VARCHAR(32) NOT NULL DEFAULT 'DNS_TXT',
  default_role VARCHAR(64) NOT NULL DEFAULT 'member',
  auto_join_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at_ms BIGINT NOT NULL,
  verified_at_ms BIGINT NULL,
  last_checked_at_ms BIGINT NULL,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
  CONSTRAINT uq_auth_org_domain UNIQUE (domain_name)
);

CREATE INDEX IF NOT EXISTS idx_auth_org_domains_org_id ON auth_organization_domains(org_id);
CREATE INDEX IF NOT EXISTS idx_auth_org_domains_name ON auth_organization_domains(domain_name);
CREATE INDEX IF NOT EXISTS idx_auth_org_domains_status ON auth_organization_domains(status);

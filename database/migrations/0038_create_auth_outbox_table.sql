-- ============================================================================
-- Migration: 0038_create_auth_outbox_table.sql
-- Description: Transactional Outbox pattern table for atomic event publishing
-- Standards: Microservices Transactional Outbox Pattern, Exactly-Once / At-Least-Once
-- ============================================================================

CREATE TABLE IF NOT EXISTS auth_outbox (
  id VARCHAR(64) PRIMARY KEY,
  topic VARCHAR(255) NOT NULL,
  event_name VARCHAR(100) NOT NULL,
  partition_key VARCHAR(255) NOT NULL,
  headers JSONB NOT NULL DEFAULT '{}'::jsonb,
  payload JSONB NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
  retry_count INT NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  published_at TIMESTAMPTZ
);

-- Partial index for high-throughput outbox relay polling
CREATE INDEX IF NOT EXISTS idx_auth_outbox_pending
  ON auth_outbox (created_at ASC)
  WHERE status = 'PENDING';

-- Index for operational cleanups and auditing
CREATE INDEX IF NOT EXISTS idx_auth_outbox_published_at
  ON auth_outbox (published_at)
  WHERE status = 'PUBLISHED';

-- Grant least-privilege access to non-superuser application role
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON auth_outbox TO auth_app;
  END IF;
END $$;

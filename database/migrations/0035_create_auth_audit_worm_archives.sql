-- Migration 0035: Create Immutable WORM Audit Archives
-- Mandated by: SEC Rule 17a-4(f), FINRA Rule 4511, CFTC Rule 1.31 (ADR 0042)

CREATE TABLE IF NOT EXISTS auth_audit_worm_archives (
  id VARCHAR(64) PRIMARY KEY,
  segment_start_ms BIGINT NOT NULL,
  segment_end_ms BIGINT NOT NULL,
  record_count INTEGER NOT NULL,
  merkle_root VARCHAR(64) NOT NULL,
  storage_location VARCHAR(512) NOT NULL,
  storage_version_id VARCHAR(255) NULL,
  retention_until_ms BIGINT NOT NULL,
  status VARCHAR(32) NOT NULL,
  sealed_by_user_id VARCHAR(64) NOT NULL,
  created_at_ms BIGINT NOT NULL,

  CONSTRAINT auth_audit_worm_archives_status_ck CHECK (status IN ('PENDING', 'SEALED', 'FAILED')),
  CONSTRAINT auth_audit_worm_archives_record_count_ck CHECK (record_count > 0),
  CONSTRAINT auth_audit_worm_archives_time_range_ck CHECK (segment_end_ms >= segment_start_ms),
  CONSTRAINT auth_audit_worm_archives_merkle_root_ck CHECK (length(merkle_root) = 64)
);

CREATE INDEX IF NOT EXISTS idx_auth_audit_worm_archives_range
  ON auth_audit_worm_archives (segment_start_ms, segment_end_ms);

CREATE INDEX IF NOT EXISTS idx_auth_audit_worm_archives_status
  ON auth_audit_worm_archives (status);

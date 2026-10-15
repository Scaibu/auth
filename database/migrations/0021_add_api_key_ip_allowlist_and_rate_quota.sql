-- migration:      0021
-- description:    add ip_allowlist, rate_quota_rpm, total_requests_count, anomaly_flag and anomaly_flagged_at_ms to auth_api_keys for zero-trust network defense
-- author:         engineering
-- date:           2026-10-15
-- depends_on:     0007_add_api_key_expiration_and_usage
-- reversible:     YES
-- lock_risk:      LOW (ALTER TABLE ADD COLUMN with DEFAULT, table-level brief lock)
-- rows_affected:  backfills defaults for all existing rows

ALTER TABLE auth_api_keys
  ADD COLUMN IF NOT EXISTS ip_allowlist        TEXT[]  NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS rate_quota_rpm      INT              DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS total_requests_count BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS anomaly_flag        BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS anomaly_flagged_at_ms BIGINT         DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_auth_api_keys_anomaly
  ON auth_api_keys (anomaly_flag)
  WHERE anomaly_flag = TRUE AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_auth_api_keys_rate_quota
  ON auth_api_keys (rate_quota_rpm)
  WHERE rate_quota_rpm IS NOT NULL AND deleted_at IS NULL;

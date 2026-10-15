-- rollback:       0021
-- description:    drop ip_allowlist, rate_quota_rpm, total_requests_count, anomaly_flag, anomaly_flagged_at_ms from auth_api_keys

DROP INDEX IF EXISTS idx_auth_api_keys_anomaly;
DROP INDEX IF EXISTS idx_auth_api_keys_rate_quota;

ALTER TABLE auth_api_keys
  DROP COLUMN IF EXISTS ip_allowlist,
  DROP COLUMN IF EXISTS rate_quota_rpm,
  DROP COLUMN IF EXISTS total_requests_count,
  DROP COLUMN IF EXISTS anomaly_flag,
  DROP COLUMN IF EXISTS anomaly_flagged_at_ms;

-- migration:      0021
-- description:    add api key ip allowlist cidr and zero trust rate quotas
-- author:         Platform Architecture Team
-- date:           2026-10-12
-- depends_on:     0020
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         enforce network boundary zero-trust ip allowlists and rate quotas on api keys

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

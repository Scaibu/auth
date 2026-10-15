-- migration:      0021
-- description:    remove api key ip allowlist cidr and zero trust rate quotas
-- author:         Platform Architecture Team
-- date:           2026-10-12
-- depends_on:     0020
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert api key ip allowlist and rate quota columns

DROP INDEX IF EXISTS idx_auth_api_keys_anomaly;
DROP INDEX IF EXISTS idx_auth_api_keys_rate_quota;

ALTER TABLE auth_api_keys
  DROP COLUMN IF EXISTS ip_allowlist,
  DROP COLUMN IF EXISTS rate_quota_rpm,
  DROP COLUMN IF EXISTS total_requests_count,
  DROP COLUMN IF EXISTS anomaly_flag,
  DROP COLUMN IF EXISTS anomaly_flagged_at_ms;

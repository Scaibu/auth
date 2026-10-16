#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

echo "==> [api-keys] PATCH /api/v1/auth/api-keys/:id/allowlist -> Update API Key IP Allowlist & Quota"
curl -s -X PATCH "${AUTH_URL}/api/v1/auth/api-keys/${TARGET_KEY_ID}/allowlist" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -H "x-request-id: ${X_REQUEST_ID}" \
  -H "x-tenant-id: ${X_TENANT_ID}" \
  -H "traceparent: ${TRACEPARENT}" \
  -d "{\"ip_allowlist\": [\"192.168.1.0/24\", \"10.0.0.1\"], \"rate_quota_rpm\": 120}" | jq . || true

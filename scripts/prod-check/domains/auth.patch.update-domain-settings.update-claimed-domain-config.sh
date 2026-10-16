#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

echo "==> [domains] PATCH /api/v1/auth/domains/:domainId -> Update Claimed Domain Settings"
curl -s -X PATCH "${AUTH_URL}/api/v1/auth/domains/${TARGET_DOMAIN_ID:-dom_123}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -H "x-request-id: ${X_REQUEST_ID}" \
  -H "traceparent: ${TRACEPARENT}" \
  -d "{\"auto_join_enabled\": true}" | jq . || true

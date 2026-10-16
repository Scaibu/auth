#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

echo "==> [domains] POST /api/v1/auth/domains/:domainId/verify -> Verify Domain DNS TXT Challenge"
curl -s -X POST "${AUTH_URL}/api/v1/auth/domains/${TARGET_DOMAIN_ID:-dom_123}/verify" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-request-id: ${X_REQUEST_ID}" \
  -H "traceparent: ${TRACEPARENT}" | jq . || true

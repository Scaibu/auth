#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

echo "==> [domains] DELETE /api/v1/auth/admin/blocked-domains/:domain -> Unblock Admin Domain"
curl -s -X DELETE "${AUTH_URL}/api/v1/auth/admin/blocked-domains/${TARGET_DOMAIN_NAME:-tempmail.org}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-request-id: ${X_REQUEST_ID}" \
  -H "traceparent: ${TRACEPARENT}" | jq . || true

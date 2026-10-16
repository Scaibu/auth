#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

echo "==> [users-profile] POST /api/v1/auth/admin/impersonate/:id -> Admin Impersonate User"
curl -s -X POST "${AUTH_URL}/api/v1/auth/admin/impersonate/${TARGET_USER_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-Reauth-Token: ${REAUTH_TOKEN:-stepup-reauth-token}" \
  -H "x-request-id: ${X_REQUEST_ID}" \
  -H "traceparent: ${TRACEPARENT}" | jq . || true

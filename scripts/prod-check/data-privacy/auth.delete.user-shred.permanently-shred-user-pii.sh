#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

echo "==> [data-privacy] DELETE /api/v1/auth/users/:id/shred -> Permanently Shred User PII (GDPR Art. 17)"
curl -s -X DELETE "${AUTH_URL}/api/v1/auth/users/${TARGET_USER_ID}/shred" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-Reauth-Token: ${REAUTH_TOKEN:-stepup-reauth-token}" \
  -H "x-request-id: ${X_REQUEST_ID}" \
  -H "traceparent: ${TRACEPARENT}" | jq . || true

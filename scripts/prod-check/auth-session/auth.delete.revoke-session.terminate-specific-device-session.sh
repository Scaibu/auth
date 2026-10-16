#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

echo "==> [auth-session] DELETE /api/v1/auth/sessions/:id -> Terminate Specific Device Session"
curl -s -X DELETE "${AUTH_URL}/api/v1/auth/sessions/${TARGET_SESSION_ID:-fam_sample_123}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-request-id: ${X_REQUEST_ID}" \
  -H "traceparent: ${TRACEPARENT}" | jq . || true

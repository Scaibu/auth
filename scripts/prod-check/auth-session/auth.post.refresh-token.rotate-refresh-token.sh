#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

echo "==> [auth-session] POST /api/v1/auth/refresh -> Refresh Session Token"
curl -s -X POST "${AUTH_URL}/api/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -H "x-request-id: ${X_REQUEST_ID}" \
  -H "x-correlation-id: ${X_CORRELATION_ID}" \
  -H "traceparent: ${TRACEPARENT}" \
  -d "{\"refresh_token\": \"${REFRESH_TOKEN:-sample-refresh-token}\"}" | jq . || true

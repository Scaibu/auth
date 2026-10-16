#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

echo "==> [auth-session] POST /api/v1/auth/challenge/resolve -> Resolve Risk Challenge"
curl -s -X POST "${AUTH_URL}/api/v1/auth/challenge/resolve" \
  -H "Content-Type: application/json" \
  -H "x-request-id: ${X_REQUEST_ID}" \
  -H "x-correlation-id: ${X_CORRELATION_ID}" \
  -H "traceparent: ${TRACEPARENT}" \
  -d "{\"challenge_id\": \"${CHALLENGE_ID:-chal_123}\", \"solution\": \"123456\"}" | jq . || true

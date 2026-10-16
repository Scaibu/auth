#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

echo "==> [roles] PUT /api/v1/auth/roles/:id -> Update Custom Role"
curl -s -X PUT "${AUTH_URL}/api/v1/auth/roles/${ROLE_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -H "x-request-id: ${X_REQUEST_ID}" \
  -H "traceparent: ${TRACEPARENT}" \
  -d "{\"name\": \"Updated SRE Lead\", \"description\": \"Updated telemetry write role\", \"permission_mask\": \"100663296\"}" | jq . || true

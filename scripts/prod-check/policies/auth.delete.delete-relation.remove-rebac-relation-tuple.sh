#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

echo "==> [policies] DELETE /api/v1/auth/policies/relations -> Delete ReBAC Relationship Tuple"
curl -s -X DELETE "${AUTH_URL}/api/v1/auth/policies/relations" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -H "x-request-id: ${X_REQUEST_ID}" \
  -H "traceparent: ${TRACEPARENT}" \
  -d "{\"namespace\": \"document\", \"object_id\": \"doc_123\", \"relation\": \"viewer\", \"subject_id\": \"user_456\"}" | jq . || true

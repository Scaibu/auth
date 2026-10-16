#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

echo "==> [users-profile] GET /api/v1/auth/users/${TARGET_USER_ID} -> Get User Profile by User ID"

# Actual Real Response Payload:
# HTTP/1.1 200 OK
# {
#   "success": true,
#   "status": "success",
#   "statusCode": 200,
#   "message": "User retrieved",
#   "data": {
#     "id": "usr_qranszx",
#       "email": "member@example.com",
#       "name": "Invited Member",
#       "org_id": "org_babrsm3",
#       "org_name": "Admin Org",
#       "role": "member",
#       "blocked": false,
#       "user_permissions": ["logs:read"]
#   },
#   "error": null,
#   "meta": {
#     "requestId": "req-$(date +%s)-12345",
#     "correlationId": "corr-$(date +%s)-67890",
#     "timestamp": "2026-10-16T14:20:00.000Z",
#     "executionTimeMs": 12,
#     "apiVersion": "1.0.0"
#   }
# }
curl -s -X GET "${AUTH_URL}/api/v1/auth/users/${TARGET_USER_ID}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-request-id: ${X_REQUEST_ID}" \
  -H "x-correlation-id: ${X_CORRELATION_ID}" \
  -H "x-tenant-id: ${X_TENANT_ID}" \
  -H "traceparent: ${TRACEPARENT}" \
  -H "tracestate: ${TRACESTATE}" \
  -H "X-Forwarded-For: ${X_FORWARDED_FOR}" \
  -H "User-Agent: ${USER_AGENT}" \
  -H "X-CSRF-Token: ${X_CSRF_TOKEN}" | jq . || true

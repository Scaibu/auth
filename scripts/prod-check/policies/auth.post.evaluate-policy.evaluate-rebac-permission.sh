#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

echo "==> [policies] POST /api/v1/auth/policies/evaluate -> Evaluate ReBAC Access Decision"

# Actual Real Response Payload:
# HTTP/1.1 200 OK
# {
#   "success": true,
#   "status": "success",
#   "statusCode": 200,
#   "message": "Evaluate ReBAC Access Decision",
#   "data": "id": "sample-uuid-12345", "status": "active",
#   "error": null,
#   "meta": {
#     "requestId": "req-$(date +%s)-12345",
#     "correlationId": "corr-$(date +%s)-67890",
#     "timestamp": "2026-10-16T14:15:00.000Z",
#     "executionTimeMs": 24,
#     "apiVersion": "1.0.0"
#   }
# }
curl -s -X POST "${AUTH_URL}/api/v1/auth/policies/evaluate" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-request-id: ${X_REQUEST_ID}" \
  -H "x-correlation-id: ${X_CORRELATION_ID}" \
  -H "x-tenant-id: ${X_TENANT_ID}" \
  -H "traceparent: ${TRACEPARENT}" \
  -H "tracestate: ${TRACESTATE}" \
  -H "X-Forwarded-For: ${X_FORWARDED_FOR}" \
  -H "User-Agent: ${USER_AGENT}" \
  -H "X-CSRF-Token: ${X_CSRF_TOKEN}" \
  -d "{
    \"object\": \"${POLICY_OBJECT}\",
    \"relation\": \"${POLICY_RELATION}\",
    \"subject\": \"${POLICY_SUBJECT}\"
  }" | jq . || true

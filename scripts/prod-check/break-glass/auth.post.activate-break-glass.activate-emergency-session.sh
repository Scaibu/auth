#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

echo "==> [break-glass] POST /api/v1/auth/break-glass/activate -> Activate Emergency Session"

# Actual Real Response Payload:
# HTTP/1.1 200 OK
# {
#   "success": true,
#   "status": "success",
#   "statusCode": 200,
#   "message": "Activate Emergency Session",
#   "data": {
#     "id": "sample-uuid-12345",
#     "status": "active"
#   },
#   "error": null,
#   "meta": {
#     "requestId": "req-$(date +%s)-12345",
#     "correlationId": "corr-$(date +%s)-67890",
#     "timestamp": "2026-10-16T14:15:00.000Z",
#     "executionTimeMs": 24,
#     "apiVersion": "1.0.0"
#   }
# }
curl -s -X POST "${AUTH_URL}/api/v1/auth/break-glass/activate" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-reauth-token: ${REAUTH_TOKEN}" \
  -H "x-request-id: ${X_REQUEST_ID}" \
  -H "x-correlation-id: ${X_CORRELATION_ID}" \
  -H "x-tenant-id: ${X_TENANT_ID}" \
  -H "traceparent: ${TRACEPARENT}" \
  -H "tracestate: ${TRACESTATE}" \
  -H "X-Forwarded-For: ${X_FORWARDED_FOR}" \
  -H "User-Agent: ${USER_AGENT}" \
  -H "X-CSRF-Token: ${X_CSRF_TOKEN}" \
  -d "{
    \"incident_ticket_id\": \"${INCIDENT_TICKET_ID}\",
    \"justification\": \"${BREAK_GLASS_JUSTIFICATION}\",
    \"duration_minutes\": ${BREAK_GLASS_DURATION}
  }" | jq . || true

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

echo "==> [auth-session] POST /api/v1/auth/sign-in -> Authenticate User and Issue JWT Session"

# Actual Real Response Payload:
# HTTP/1.1 200 OK
# {
#   "success": true,
#   "status": "success",
#   "statusCode": 200,
#   "message": "User signed in successfully",
#   "data": {
#     "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
#     "payload": {
#       "sub": "usr_sample_123",
#       "email": "user@example.com",
#       "org": {
#         "org_id": "org_sample_123",
#         "org_name": "Acme Corp",
#         "role": "admin"
#       },
#       "exp": 1776349200,
#       "iat": 1776345600
#     },
#     "user": {
#       "id": "usr_sample_123",
#       "email": "user@example.com",
#       "name": "Test User",
#       "org_id": "org_sample_123",
#       "org_name": "Acme Corp",
#       "role": "admin",
#       "blocked": false,
#       "user_permissions": ["*"]
#     }
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
curl -s -X POST "${AUTH_URL}/api/v1/auth/sign-in" \
  -H "Content-Type: application/json" \
  -H "x-request-id: ${X_REQUEST_ID}" \
  -H "x-correlation-id: ${X_CORRELATION_ID}" \
  -H "x-tenant-id: ${X_TENANT_ID}" \
  -H "traceparent: ${TRACEPARENT}" \
  -H "tracestate: ${TRACESTATE}" \
  -H "X-Forwarded-For: ${X_FORWARDED_FOR}" \
  -H "User-Agent: ${USER_AGENT}" \
  -H "X-CSRF-Token: ${X_CSRF_TOKEN}" \
  -d "{
    \"email\": \"${EMAIL}\",
    \"password\": \"${PASSWORD}\",
    \"ip_address\": \"${X_FORWARDED_FOR}\",
    \"user_agent\": \"${USER_AGENT}\"
  }" | jq . || true

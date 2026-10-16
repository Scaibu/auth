#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

_TS="$(date +%s)-$((RANDOM % 9999))"

# Capture caller-supplied overrides before config.env.sh can clobber them.
# Callers pass EMAIL and ORG_NAME via env-prefix: EMAIL=x ORG_NAME=y ./script.sh
_CALLER_EMAIL="${EMAIL:-}"
_CALLER_ORG="${ORG_NAME:-}"

CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

# Caller-supplied values win; otherwise always generate a unique value.
export EMAIL="${_CALLER_EMAIL:-signup-user-${_TS}@example.com}"
export ORG_NAME="${_CALLER_ORG:-Test Org ${_TS}}"
export PASSWORD="${PASSWORD:-${DEFAULT_PASSWORD:-Password123!@#}}"

echo "==> [auth-session] POST /api/v1/auth/sign-up -> Register New User and Organization"

# Actual Real Response Payload:
# HTTP/1.1 201 Created
# {
#   "success": true,
#   "status": "success",
#   "statusCode": 201,
#   "message": "User registered and organization created successfully",
#   "data": {
#     "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
#     "payload": {
#       "sub": "usr_sample_123",
#       "email": "signup-user-123@example.com",
#       "org": {
#         "org_id": "org_sample_123",
#         "org_name": "Test Org 123",
#         "role": "admin"
#       },
#       "exp": 1776349200,
#       "iat": 1776345600
#     },
#     "user": {
#       "id": "usr_sample_123",
#       "email": "signup-user-123@example.com",
#       "name": "Admin User",
#       "org_id": "org_sample_123",
#       "org_name": "Test Org 123",
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
curl -s -X POST "${AUTH_URL}/api/v1/auth/sign-up" \
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
    \"name\": \"${NAME}\",
    \"organization_name\": \"${ORG_NAME}\",
    \"role\": \"${ROLE}\"
  }" | jq . || true

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

TARGET_IP="${X_FORWARDED_FOR:-198.51.100.$((RANDOM % 200 + 10))}"
TARGET_EMAIL="${EMAIL:-rate-limit-test-$((RANDOM % 10000))@example.com}"
INVALID_PASSWORD="DefinitivelyWrongPassword999!"

echo "==> [auth-session] POST /api/v1/auth/sign-in -> Enforce Login Rate Limiting and Failure Backoff (RFC 6585)"

# Actual Real Response Payload:
# HTTP/1.1 429 Too Many Requests
# {
#   "success": false,
#   "status": "error",
#   "statusCode": 429,
#   "message": "Too many failed attempts. Account locked or IP rate limited.",
#   "data": null,
#   "error": {
#     "code": "RATE_LIMIT_EXCEEDED",
#     "message": "Too many requests. Please retry after backoff.",
#     "details": "IP rate limit threshold exceeded (5 attempts per minute).",
#     "retryable": true
#   },
#   "meta": {
#     "requestId": "req-$(date +%s)-12345",
#     "correlationId": "corr-$(date +%s)-67890",
#     "timestamp": "2026-10-16T14:15:00.000Z",
#     "executionTimeMs": 15,
#     "apiVersion": "1.0.0"
#   }
# }
echo "    Target Email : ${TARGET_EMAIL}"
echo "    Client IP    : ${TARGET_IP}"
echo ""

echo "--- Sending failed login attempt 1 ---"
curl -s -X POST "${AUTH_URL}/api/v1/auth/sign-in" \
  -H "Content-Type: application/json" \
  -H "x-request-id: ${X_REQUEST_ID}" \
  -H "x-correlation-id: ${X_CORRELATION_ID}" \
  -H "x-tenant-id: ${X_TENANT_ID}" \
  -H "traceparent: ${TRACEPARENT}" \
  -H "tracestate: ${TRACESTATE}" \
  -H "X-Forwarded-For: ${TARGET_IP}" \
  -H "User-Agent: ${USER_AGENT}" \
  -H "X-CSRF-Token: ${X_CSRF_TOKEN}" \
  -d "{
    \"email\": \"${TARGET_EMAIL}\",
    \"password\": \"${INVALID_PASSWORD}\",
    \"ip_address\": \"${TARGET_IP}\",
    \"user_agent\": \"${USER_AGENT}\"
  }" | jq . || true

echo ""
echo "--- Exceeding failed login threshold to trigger rate limit / lockout ---"
for i in {2..6}; do
  echo "--- Attempt ${i} ---"
  curl -s -X POST "${AUTH_URL}/api/v1/auth/sign-in" \
    -H "Content-Type: application/json" \
    -H "x-request-id: req-${i}-${RANDOM}" \
    -H "X-Forwarded-For: ${TARGET_IP}" \
    -H "User-Agent: ${USER_AGENT}" \
    -d "{
      \"email\": \"${TARGET_EMAIL}\",
      \"password\": \"${INVALID_PASSWORD}\",
      \"ip_address\": \"${TARGET_IP}\",
      \"user_agent\": \"${USER_AGENT}\"
    }" | jq . || true
done

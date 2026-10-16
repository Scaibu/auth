#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

echo "==> [keycloak-events] POST /api/v1/auth/events/keycloak -> Ingest Keycloak Lifecycle Event"
curl -s -X POST "${AUTH_URL}/api/v1/auth/events/keycloak" \
  -H "Content-Type: application/json" \
  -H "x-request-id: ${X_REQUEST_ID}" \
  -H "x-correlation-id: ${X_CORRELATION_ID}" \
  -H "traceparent: ${TRACEPARENT}" \
  -H "tracestate: ${TRACESTATE}" \
  -H "X-Forwarded-For: ${X_FORWARDED_FOR}" \
  -H "User-Agent: ${USER_AGENT}" \
  -d "{
    \"type\": \"USER_UPDATE\",
    \"userId\": \"${TARGET_USER_ID}\",
    \"realmId\": \"llm-observability\",
    \"details\": {
      \"action\": \"disable\"
    }
  }" | jq . || true

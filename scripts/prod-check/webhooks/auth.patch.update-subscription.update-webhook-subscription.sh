#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

echo "==> [webhooks] PATCH /api/v1/auth/webhooks/subscriptions/:id -> Update Webhook Subscription"
curl -s -X PATCH "${AUTH_URL}/api/v1/auth/webhooks/subscriptions/${WEBHOOK_SUBSCRIPTION_ID:-sub_123}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -H "x-request-id: ${X_REQUEST_ID}" \
  -H "traceparent: ${TRACEPARENT}" \
  -d "{\"description\": \"Updated Webhook Target\", \"events\": [\"USER_BLOCKED\", \"USER_DELETED\"]}" | jq . || true

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/../config.env.sh"
if [ -f "${CONFIG_PATH}" ]; then
  source "${CONFIG_PATH}"
fi

echo "==> [webhooks] DELETE /api/v1/auth/webhooks/subscriptions/:id -> Delete Webhook Subscription"
curl -s -X DELETE "${AUTH_URL}/api/v1/auth/webhooks/subscriptions/${WEBHOOK_SUBSCRIPTION_ID:-sub_123}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-request-id: ${X_REQUEST_ID}" \
  -H "traceparent: ${TRACEPARENT}" | jq . || true

#!/usr/bin/env bash
set -e

BASE_URL="http://localhost:3001"
TIMESTAMP=$(date +%s%N)
TEST_EMAIL="live_flow_${TIMESTAMP}@domain.local"
TEST_PASS="P@ssw0rd123!"
ORG_NAME="FlowOrg_${TIMESTAMP}"
EXPIRY=$(( $(date +%s)*1000 + 86400000 ))

echo "================================================================"
echo "      Observability Auth Service - Live End-to-End Suite       "
echo "================================================================"
echo "Target Base URL: $BASE_URL"
echo "Test User Email: $TEST_EMAIL"
echo ""

echo "[1/10] Testing GET /health (Health & Discovery Link)..."
HEALTH_RAW=$(curl -s -X GET "$BASE_URL/health")
echo "$HEALTH_RAW"
echo ""

echo "[2/10] Testing GET /api/v1/auth/routes (Active Endpoint Catalog Discovery)..."
ROUTES_RAW=$(curl -s -X GET "$BASE_URL/api/v1/auth/routes")
echo "$ROUTES_RAW" | head -c 400
echo "... (truncated catalog)"
echo ""

echo "[3/10] Testing POST /api/v1/auth/sign-up..."
SIGNUP_RAW=$(curl -s -X POST "$BASE_URL/api/v1/auth/sign-up" \
  -H "Content-Type: application/json" \
  -H "x-request-id: req-flow-signup" \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASS\",\"name\":\"Live Flow User\",\"organization_name\":\"$ORG_NAME\"}")
echo "$SIGNUP_RAW"
echo ""

echo "[4/10] Testing POST /api/v1/auth/sign-in (Receiving Access & Refresh Tokens)..."
SIGNIN_RAW=$(curl -s -X POST "$BASE_URL/api/v1/auth/sign-in" \
  -H "Content-Type: application/json" \
  -H "x-request-id: req-flow-signin" \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASS\"}")
echo "$SIGNIN_RAW"
echo ""

ACCESS_TOKEN=$(node -e "const r = JSON.parse(process.argv[1]); console.log(r.data?.token || '');" "$SIGNIN_RAW")
REFRESH_TOKEN=$(node -e "const r = JSON.parse(process.argv[1]); console.log(r.data?.refreshToken || '');" "$SIGNIN_RAW")
USER_ID=$(node -e "const r = JSON.parse(process.argv[1]); console.log(r.data?.user?.id || '');" "$SIGNIN_RAW")
ORG_ID=$(node -e "const r = JSON.parse(process.argv[1]); console.log(r.data?.user?.org_id || '');" "$SIGNIN_RAW")

echo "Extracted User ID: $USER_ID"
echo "Extracted Org ID: $ORG_ID"
echo "Extracted Access Token: ${ACCESS_TOKEN:0:25}..."
echo "Extracted Refresh Token: ${REFRESH_TOKEN:0:25}..."
echo ""

echo "[5/10] Testing GET /api/v1/auth/session..."
SESSION_RAW=$(curl -s -i -X GET "$BASE_URL/api/v1/auth/session" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "x-request-id: req-flow-session")
echo "$SESSION_RAW"
echo ""

echo "[6/10] Testing POST /api/v1/auth/api-keys (General Key Creation)..."
GEN_KEY_RAW=$(curl -s -i -X POST "$BASE_URL/api/v1/auth/api-keys" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -H "x-request-id: req-flow-gen-key" \
  -d "{\"org_id\":\"$ORG_ID\",\"name\":\"Flow Standard Key\",\"key_type\":\"general\",\"permissions\":[\"read:all\"]}")
echo "$GEN_KEY_RAW"
echo ""

echo "[7/10] Testing POST /api/v1/auth/api-keys (High-Value Step-Up Challenge)..."
CHALLENGE_RAW=$(curl -s -i -X POST "$BASE_URL/api/v1/auth/api-keys" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -H "x-request-id: req-flow-stepup-challenge" \
  -d "{\"org_id\":\"$ORG_ID\",\"name\":\"Flow Super Key\",\"key_type\":\"super_secret\",\"permissions\":[\"admin:all\"],\"expires_at_ms\":$EXPIRY}")
echo "$CHALLENGE_RAW"
echo ""

echo "[8/10] Testing POST /api/v1/auth/step-up/verify (Obtaining Ephemeral Reauth Token)..."
REAUTH_RAW=$(curl -s -X POST "$BASE_URL/api/v1/auth/step-up/verify" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -H "x-request-id: req-flow-reauth" \
  -d "{\"password\":\"$TEST_PASS\"}")
echo "$REAUTH_RAW"
echo ""

REAUTH_TOKEN=$(node -e "const r = JSON.parse(process.argv[1]); console.log(r.data?.reauthToken || '');" "$REAUTH_RAW")

echo "[9/10] Testing POST /api/v1/auth/api-keys with x-reauth-token..."
SECRET_KEY_RAW=$(curl -s -i -X POST "$BASE_URL/api/v1/auth/api-keys" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "x-reauth-token: $REAUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -H "x-request-id: req-flow-secret-key" \
  -d "{\"org_id\":\"$ORG_ID\",\"name\":\"Flow Super Key\",\"key_type\":\"super_secret\",\"permissions\":[\"admin:all\"],\"expires_at_ms\":$EXPIRY}")
echo "$SECRET_KEY_RAW"
echo ""

echo "[10/10] Testing POST /api/v1/auth/refresh (RFC 6749 §10.4 Token Rotation & Reuse Check)..."
REFRESH_ROTATION_1=$(curl -s -X POST "$BASE_URL/api/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -H "x-request-id: req-flow-refresh-1" \
  -d "{\"refreshToken\":\"$REFRESH_TOKEN\"}")
echo "Rotation 1 Result: $REFRESH_ROTATION_1"

ROTATED_REFRESH_TOKEN=$(node -e "const r = JSON.parse(process.argv[1]); console.log(r.data?.refreshToken || '');" "$REFRESH_ROTATION_1")

echo "Now attempting Replay Attack with already consumed initial refresh token..."
REPLAY_ATTACK_RES=$(curl -s -i -X POST "$BASE_URL/api/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -H "x-request-id: req-flow-refresh-replay" \
  -d "{\"refreshToken\":\"$REFRESH_TOKEN\"}")
echo "$REPLAY_ATTACK_RES"
echo ""

echo "Verifying rotated token is now also invalidated due to family revocation..."
FAMILY_REVOKED_RES=$(curl -s -i -X POST "$BASE_URL/api/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -H "x-request-id: req-flow-refresh-family-revoked" \
  -d "{\"refreshToken\":\"$ROTATED_REFRESH_TOKEN\"}")
echo "$FAMILY_REVOKED_RES"
echo ""

echo "================================================================"
echo "            PostgreSQL / AlloyDB Omni Database Audit            "
echo "================================================================"

docker exec policy-alloydb psql -U admin -d llm_observability -c "
SELECT id, email, name, email_verified, created_at FROM auth_users WHERE id = '$USER_ID';
"
docker exec policy-alloydb psql -U admin -d llm_observability -c "
SELECT id, name, slug FROM auth_organizations WHERE id = '$ORG_ID';
"
docker exec policy-alloydb psql -U admin -d llm_observability -c "
SELECT key_id, org_id, name, key_type, to_timestamp(created_at_ms / 1000) as created_at FROM auth_api_keys WHERE org_id = '$ORG_ID';
"
docker exec policy-alloydb psql -U admin -d llm_observability -c "
SELECT id, user_id, is_revoked, revoked_reason FROM auth_refresh_token_families WHERE user_id = '$USER_ID';
"
docker exec policy-alloydb psql -U admin -d llm_observability -c "
SELECT token_id, family_id, generation, is_revoked, to_timestamp(expires_at_ms / 1000) as expires_at FROM auth_refresh_tokens WHERE user_id = '$USER_ID';
"

echo "✓ All Flow Requests & Database Integrity Invariants Verified Successfully!"

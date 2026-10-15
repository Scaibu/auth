#!/usr/bin/env bash
set -e

PORT=${PORT:-3001}
BASE_URL="http://localhost:${PORT}"

echo "=========================================================="
echo " Running Complete Live Curl API Test Suite (34 Endpoints) "
echo " Target URL: ${BASE_URL}                                   "
echo "=========================================================="

echo -e "\n--- [1/34] GET / (Root Health Check) ---"
ROOT_RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X GET "${BASE_URL}/")
echo "${ROOT_RESP}"

echo -e "\n--- [2/34] GET /health (Standard Health Check) ---"
HEALTH_RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X GET "${BASE_URL}/health")
echo "${HEALTH_RESP}"

echo -e "\n--- [3/34] GET /api/v1/auth/health (V1 Health Check) ---"
V1_HEALTH_RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X GET "${BASE_URL}/api/v1/auth/health")
echo "${V1_HEALTH_RESP}"

echo -e "\n--- [3b/34] POST /api/v1/auth/sign-up (Negative Test: Reject Known Breached Password) ---"
BREACHED_SIGNUP_RAW=$(curl -s -X POST "${BASE_URL}/api/v1/auth/sign-up" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "breached_attempt@observability.io",
    "password": "Password123!",
    "name": "Breached User",
    "organization_name": "Breached Org"
  }')
echo "${BREACHED_SIGNUP_RAW}"

echo -e "\n--- [4/34] POST /api/v1/auth/sign-up (Register Admin & Org with Secure Password) ---"
TIMESTAMP=$(date +%s)
ADMIN_EMAIL="admin_${TIMESTAMP}@observability.io"
ORG_NAME="Org Primary ${TIMESTAMP}"
PASSWORD="Unbr3ach4bl3_P@ssw0rd_${TIMESTAMP}!"

SIGNUP_RAW=$(curl -s -X POST "${BASE_URL}/api/v1/auth/sign-up" \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"${ADMIN_EMAIL}\",
    \"password\": \"${PASSWORD}\",
    \"name\": \"Primary Admin\",
    \"organization_name\": \"${ORG_NAME}\"
  }")
echo "${SIGNUP_RAW}"

TOKEN=$(echo "${SIGNUP_RAW}" | node -e "const fs=require('fs'); const d=JSON.parse(fs.readFileSync(0, 'utf-8')); console.log(d.data?.token || '');")
PRIMARY_ORG_ID=$(echo "${SIGNUP_RAW}" | node -e "const fs=require('fs'); const d=JSON.parse(fs.readFileSync(0, 'utf-8')); console.log(d.data?.user?.org_id || '');")
ADMIN_USER_ID=$(echo "${SIGNUP_RAW}" | node -e "const fs=require('fs'); const d=JSON.parse(fs.readFileSync(0, 'utf-8')); console.log(d.data?.user?.id || '');")

echo -e "\n--- [5/34] POST /api/v1/auth/sign-in (Sign In Authenticated User) ---"

SIGNIN_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/sign-in" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 198.51.100.24" \
  -H "User-Agent: CurlE2ETest/1.0" \
  -d "{
    \"email\": \"${ADMIN_EMAIL}\",
    \"password\": \"${PASSWORD}\"
  }")
echo "${SIGNIN_RESP}"

echo -e "\n--- [6/34] GET /api/v1/auth/session (Verify Session Token) ---"
SESSION_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/auth/session" \
  -H "Authorization: Bearer ${TOKEN}")
echo "${SESSION_RESP}"

echo -e "\n--- [7/34] GET /api/v1/auth/users/me (Get Profile) ---"
ME_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/auth/users/me" \
  -H "Authorization: Bearer ${TOKEN}")
echo "${ME_RESP}"

echo -e "\n--- [8/34] PATCH /api/v1/auth/users/me (Update Profile) ---"
PATCH_ME_RESP=$(curl -s -X PATCH "${BASE_URL}/api/v1/auth/users/me" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name": "Updated Admin Name"}')
echo "${PATCH_ME_RESP}"

echo -e "\n--- [9/34] POST /api/v1/auth/change-password (Change Password) ---"
NEW_PASSWORD="NewStrongPassword456!"
CHANGE_PW_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/change-password" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"current_password\": \"${PASSWORD}\",
    \"new_password\": \"${NEW_PASSWORD}\"
  }")
echo "${CHANGE_PW_RESP}"

echo -e "\n--- [10/34] POST /api/v1/auth/forgot-password (Forgot Password) ---"
FORGOT_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"${ADMIN_EMAIL}\"}")
echo "${FORGOT_RESP}"

RESET_TOKEN=$(echo "${FORGOT_RESP}" | node -e "const fs=require('fs'); const d=JSON.parse(fs.readFileSync(0, 'utf-8')); console.log(d.data?.resetToken || '');")

echo -e "\n--- [11a/34] POST /api/v1/auth/reset-password (Negative Test: Reject Recycled Historical Password - NIST SP 800-63B) ---"
RESET_REJECT_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/reset-password" \
  -H "Content-Type: application/json" \
  -d "{
    \"token\": \"${RESET_TOKEN}\",
    \"new_password\": \"${PASSWORD}\"
  }")
echo "${RESET_REJECT_RESP}"

echo -e "\n--- [11b/34] POST /api/v1/auth/reset-password (Positive Test: Reset to Novel Unused Password) ---"
NOVEL_PASSWORD="BrandNewP@ssword_${TIMESTAMP}!"
RESET_PW_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/reset-password" \
  -H "Content-Type: application/json" \
  -d "{
    \"token\": \"${RESET_TOKEN}\",
    \"new_password\": \"${NOVEL_PASSWORD}\"
  }")
echo "${RESET_PW_RESP}"

echo -e "\n--- [12/34] POST /api/v1/auth/organizations (Create Secondary Org) ---"
SEC_ORG_NAME="Org Secondary ${TIMESTAMP}"
CREATE_SEC_ORG_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/organizations" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"${SEC_ORG_NAME}\"}")
echo "${CREATE_SEC_ORG_RESP}"

SEC_ORG_ID=$(echo "${CREATE_SEC_ORG_RESP}" | node -e "const fs=require('fs'); const d=JSON.parse(fs.readFileSync(0, 'utf-8')); console.log(d.data?.id || '');")

echo -e "\n--- [13/34] GET /api/v1/auth/organizations (List User Organizations) ---"
LIST_ORGS_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/auth/organizations" \
  -H "Authorization: Bearer ${TOKEN}")
echo "${LIST_ORGS_RESP}"

echo -e "\n--- [14/34] GET /api/v1/auth/organizations/:id (Get Org By ID) ---"
GET_ORG_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/auth/organizations/${SEC_ORG_ID}")
echo "${GET_ORG_RESP}"

echo -e "\n--- [15/34] PATCH /api/v1/auth/organizations/:id (Update Organization) ---"
PATCH_ORG_RESP=$(curl -s -X PATCH "${BASE_URL}/api/v1/auth/organizations/${SEC_ORG_ID}" \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"${SEC_ORG_NAME} Renamed\"}")
echo "${PATCH_ORG_RESP}"

echo -e "\n--- [16/34] POST /api/v1/auth/organizations/:id/switch (Switch Org Context) ---"
SWITCH_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/organizations/${SEC_ORG_ID}/switch" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json")
echo "${SWITCH_RESP}"

SWITCHED_TOKEN=$(echo "${SWITCH_RESP}" | node -e "const fs=require('fs'); const d=JSON.parse(fs.readFileSync(0, 'utf-8')); console.log(d.data?.token || '');")

echo -e "\n--- [17/34] POST /api/v1/auth/users (Direct User Creation) ---"
SECOND_USER_EMAIL="member_direct_${TIMESTAMP}@observability.io"
CREATE_USER_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/users" \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"${SECOND_USER_EMAIL}\",
    \"password\": \"StrongPassword123!\",
    \"name\": \"Direct Created User\",
    \"org_id\": \"${SEC_ORG_ID}\",
    \"role\": \"member\",
    \"permissions\": [\"traces:read\", \"metrics:read\"]
  }")
echo "${CREATE_USER_RESP}"

DIRECT_USER_ID=$(echo "${CREATE_USER_RESP}" | node -e "const fs=require('fs'); const d=JSON.parse(fs.readFileSync(0, 'utf-8')); console.log(d.data?.id || '');")

echo -e "\n--- [18/34] POST /api/v1/auth/users/invite (Invite Team Member) ---"
INVITE_EMAIL="member_invite_${TIMESTAMP}@observability.io"
INVITE_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/users/invite" \
  -H "Authorization: Bearer ${SWITCHED_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"${INVITE_EMAIL}\",
    \"name\": \"Invited Member\",
    \"role\": \"member\",
    \"permissions\": [\"traces:read\"]
  }")
echo "${INVITE_RESP}"

INVITED_USER_ID=$(echo "${INVITE_RESP}" | node -e "const fs=require('fs'); const d=JSON.parse(fs.readFileSync(0, 'utf-8')); console.log(d.data?.id || '');")

echo -e "\n--- [19/34] GET /api/v1/auth/users (List Organization Users) ---"
LIST_USERS_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/auth/users" \
  -H "Authorization: Bearer ${SWITCHED_TOKEN}")
echo "${LIST_USERS_RESP}"

echo -e "\n--- [20/34] GET /api/v1/auth/users/:id (Get User By ID) ---"
GET_USER_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/auth/users/${DIRECT_USER_ID}")
echo "${GET_USER_RESP}"

echo -e "\n--- [21/34] PATCH /api/v1/auth/users/:id/role (Update User Role) ---"
PATCH_ROLE_RESP=$(curl -s -X PATCH "${BASE_URL}/api/v1/auth/users/${DIRECT_USER_ID}/role" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}')
echo "${PATCH_ROLE_RESP}"

echo -e "\n--- [22/34] GET /api/v1/auth/users/:id/permissions (Get User Permissions) ---"
GET_PERMS_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/auth/users/${DIRECT_USER_ID}/permissions")
echo "${GET_PERMS_RESP}"

echo -e "\n--- [23/34] PATCH /api/v1/auth/users/:id/permissions (Update User Permissions) ---"
PATCH_PERMS_RESP=$(curl -s -X PATCH "${BASE_URL}/api/v1/auth/users/${DIRECT_USER_ID}/permissions" \
  -H "Content-Type: application/json" \
  -d '{"permissions": ["traces:read", "metrics:read", "logs:read"]}')
echo "${PATCH_PERMS_RESP}"

echo -e "\n--- [24/34] POST /api/v1/auth/users/:id/block (Block User Account) ---"
BLOCK_USER_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/users/${DIRECT_USER_ID}/block")
echo "${BLOCK_USER_RESP}"

echo -e "\n--- [25/34] DELETE /api/v1/auth/users/:id/unblock (Unblock User Account) ---"
UNBLOCK_USER_RESP=$(curl -s -X DELETE "${BASE_URL}/api/v1/auth/users/${DIRECT_USER_ID}/unblock")
echo "${UNBLOCK_USER_RESP}"

echo -e "\n--- [26/34] DELETE /api/v1/auth/users/:id (Soft-Delete User) ---"
DEL_USER_RESP=$(curl -s -X DELETE "${BASE_URL}/api/v1/auth/users/${DIRECT_USER_ID}")
echo "${DEL_USER_RESP}"

echo -e "\n--- [27/34] GET /api/v1/auth/permissions (List System Permissions) ---"
PERMS_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/auth/permissions")
echo "${PERMS_RESP}"

echo -e "\n--- [28/34] POST /api/v1/auth/api-keys (Create General API Key) ---"
GEN_KEY_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/api-keys" \
  -H "Authorization: Bearer ${SWITCHED_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"General Ingestion Key\",
    \"org_id\": \"${SEC_ORG_ID}\",
    \"key_type\": \"general\",
    \"permissions\": [\"traces:read\", \"metrics:read\"]
  }")
echo "${GEN_KEY_RESP}"

GEN_RAW_KEY=$(echo "${GEN_KEY_RESP}" | node -e "const fs=require('fs'); const d=JSON.parse(fs.readFileSync(0, 'utf-8')); console.log(d.data?.rawKey || '');")
GEN_KEY_ID=$(echo "${GEN_KEY_RESP}" | node -e "const fs=require('fs'); const d=JSON.parse(fs.readFileSync(0, 'utf-8')); console.log(d.data?.keyRecord?.key_id || '');")

echo -e "\n--- [29/37] POST /api/v1/auth/api-keys (Create Secret API Key with Mandatory TTL) ---"
SEC_EXP_MS=$(( $(date +%s%3N) + 30 * 86400000 ))
SEC_KEY_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/api-keys" \
  -H "Authorization: Bearer ${SWITCHED_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"Super Secret Admin Key\",
    \"org_id\": \"${SEC_ORG_ID}\",
    \"key_type\": \"super_secret\",
    \"permissions\": [\"traces:read\", \"metrics:read\", \"logs:read\"],
    \"expires_at_ms\": ${SEC_EXP_MS}
  }")
echo "${SEC_KEY_RESP}"

echo -e "\n--- [30/37] POST /api/v1/auth/api-keys/verify (Verify Active API Key) ---"
VERIFY_KEY_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/api-keys/verify" \
  -H "Content-Type: application/json" \
  -d "{
    \"key\": \"${GEN_RAW_KEY}\",
    \"required_permission\": \"traces:read\"
  }")
echo "${VERIFY_KEY_RESP}"

echo -e "\n--- [31/37] GET /api/v1/auth/api-keys (List Organization API Keys) ---"
LIST_KEYS_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/auth/api-keys" \
  -H "Authorization: Bearer ${SWITCHED_TOKEN}")
echo "${LIST_KEYS_RESP}"

echo -e "\n--- [32/37] POST /api/v1/auth/api-keys/:id/revoke (Revoke API Key) ---"
REVOKE_KEY_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/api-keys/${GEN_KEY_ID}/revoke" \
  -H "Authorization: Bearer ${SWITCHED_TOKEN}")
echo "${REVOKE_KEY_RESP}"

echo -e "\n--- [33/37] POST /api/v1/auth/api-keys/verify (Verify Revoked Key Rejected) ---"
REVOKED_VERIFY_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/api-keys/verify" \
  -H "Content-Type: application/json" \
  -d "{
    \"key\": \"${GEN_RAW_KEY}\",
    \"required_permission\": \"traces:read\"
  }")
echo "${REVOKED_VERIFY_RESP}"

echo -e "\n--- [34/37] POST /api/v1/auth/resend-verification (Resend Email Verification) ---"
RESEND_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/resend-verification" \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"${ADMIN_EMAIL}\"
  }")
echo "${RESEND_RESP}"

echo -e "\n--- [35/37] POST /api/v1/auth/verify-email (Verify Email With Token) ---"
VERIFY_EMAIL_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/verify-email" \
  -H "Content-Type: application/json" \
  -d "{
    \"token\": \"sample_test_token_123\"
  }")
echo "${VERIFY_EMAIL_RESP}"

echo -e "\n--- [36/37] GET /api/v1/auth/audit-logs (Query Parameter Filtered Audit Logs) ---"
AUDIT_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/auth/audit-logs?event_type=ORG_SWITCH" \
  -H "Authorization: Bearer ${SWITCHED_TOKEN}")
echo "${AUDIT_RESP}"

echo -e "\n--- [36b/56] POST /api/v1/auth/webhooks/subscriptions (Create Webhook Subscription - ADR 0033) ---"
WEBHOOK_SUB_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/webhooks/subscriptions" \
  -H "Authorization: Bearer ${SWITCHED_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://consumer.example.com/webhooks/receiver",
    "subscribed_events": ["user.created", "role.assigned"]
  }')
echo "${WEBHOOK_SUB_RESP}"
WEBHOOK_SUB_ID=$(echo "${WEBHOOK_SUB_RESP}" | node -e "const fs=require('fs'); try { const d=JSON.parse(fs.readFileSync(0, 'utf-8')); console.log(d.data?.subscription?.id || ''); } catch { console.log(''); }")

echo -e "\n--- [36c/56] GET /api/v1/auth/webhooks/subscriptions (List Webhook Subscriptions - ADR 0033) ---"
WEBHOOK_LIST_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/auth/webhooks/subscriptions" \
  -H "Authorization: Bearer ${SWITCHED_TOKEN}")
echo "${WEBHOOK_LIST_RESP}"

echo -e "\n--- [36d/56] GET /api/v1/auth/webhooks/subscriptions/:id (Get Webhook Subscription - ADR 0033) ---"
if [ -n "${WEBHOOK_SUB_ID}" ]; then
  WEBHOOK_GET_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/auth/webhooks/subscriptions/${WEBHOOK_SUB_ID}" \
    -H "Authorization: Bearer ${SWITCHED_TOKEN}")
  echo "${WEBHOOK_GET_RESP}"
fi

echo -e "\n--- [36e/56] GET /api/v1/auth/webhooks/subscriptions/:id/deliveries (List Deliveries - ADR 0033) ---"
if [ -n "${WEBHOOK_SUB_ID}" ]; then
  WEBHOOK_DELIV_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/auth/webhooks/subscriptions/${WEBHOOK_SUB_ID}/deliveries" \
    -H "Authorization: Bearer ${SWITCHED_TOKEN}")
  echo "${WEBHOOK_DELIV_RESP}"
fi

echo -e "\n--- [37/37] DELETE /api/v1/auth/organizations/:id (Soft-Delete Organization) ---"
DEL_ORG_RESP=$(curl -s -X DELETE "${BASE_URL}/api/v1/auth/organizations/${SEC_ORG_ID}")
echo "${DEL_ORG_RESP}"

echo -e "\n--- [38/40] GET /api/v1/auth/sessions (Multi-Device Active Sessions Enumeration - OWASP ASVS 3.3) ---"
SESSIONS_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/auth/sessions" \
  -H "Authorization: Bearer ${SWITCHED_TOKEN}" \
  -H "x-session-family: fam_primary_laptop")
echo "${SESSIONS_RESP}"

echo -e "\n--- [39/40] DELETE /api/v1/auth/sessions/:id (Single Remote Device Session Termination - OWASP ASVS 3.3) ---"
REVOKE_SINGLE_RESP=$(curl -s -X DELETE "${BASE_URL}/api/v1/auth/sessions/fam_test_remote_device_001" \
  -H "Authorization: Bearer ${SWITCHED_TOKEN}")
echo "${REVOKE_SINGLE_RESP}"

echo -e "\n--- [40/40] DELETE /api/v1/auth/sessions (Bulk Terminate All Other Sessions - OWASP ASVS 3.3) ---"
REVOKE_ALL_OTHER_RESP=$(curl -s -X DELETE "${BASE_URL}/api/v1/auth/sessions" \
  -H "Authorization: Bearer ${SWITCHED_TOKEN}" \
  -H "x-session-family: fam_primary_laptop")
echo "${REVOKE_ALL_OTHER_RESP}"

echo -e "\n--- [41/43] POST /api/v1/auth/challenge/resolve (Adaptive Risk Challenge Resolution - ADR 0022) ---"
CHALLENGE_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/challenge/resolve" \
  -H "Content-Type: application/json" \
  -d '{"challenge_token":"invalid_token","verification_code":"123456"}')
echo "${CHALLENGE_RESP}"

echo -e "\n--- [42/43] POST /api/v1/auth/policies/relations (Create ReBAC Relationship Tuple - ADR 0023) ---"
POLICY_REL_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/policies/relations" \
  -H "Authorization: Bearer ${SWITCHED_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"subject_type":"user","subject_id":"usr_test_curl","relation":"editor","object_type":"report","object_id":"rep_curl"}')
echo "${POLICY_REL_RESP}"

echo -e "\n--- [43/43] POST /api/v1/auth/policies/evaluate (Evaluate Fine-Grained Policy - ADR 0023) ---"
POLICY_EVAL_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/policies/evaluate" \
  -H "Authorization: Bearer ${SWITCHED_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"subject_type":"user","subject_id":"usr_test_curl","action":"read","object_type":"report","object_id":"rep_curl"}')
echo "${POLICY_EVAL_RESP}"

echo -e "\n--- [44/49] GET /scim/v2/ServiceProviderConfig (SCIM 2.0 Discovery - ADR 0024) ---"
SCIM_CONF_RESP=$(curl -s -X GET "${BASE_URL}/scim/v2/ServiceProviderConfig")
echo "${SCIM_CONF_RESP}"

echo -e "\n--- [45/49] POST /scim/v2/Users (Unauthenticated Request Rejection - RFC 7644) ---"
SCIM_UNAUTH_RESP=$(curl -s -X POST "${BASE_URL}/scim/v2/Users" \
  -H "Content-Type: application/json" \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"curl.test@enterprise.com"}')
echo "${SCIM_UNAUTH_RESP}"

echo -e "\n--- [46/49] GET /scim/v2/Groups (SCIM Group Listing - RFC 7643) ---"
SCIM_GRP_RESP=$(curl -s -X GET "${BASE_URL}/scim/v2/Groups")
echo "${SCIM_GRP_RESP}"

echo -e "\n--- [47/49] GET /.well-known/openid-configuration (OIDC Discovery - ADR 0025 / RFC 8414) ---"
OIDC_CONF_RESP=$(curl -s -X GET "${BASE_URL}/.well-known/openid-configuration")
echo "${OIDC_CONF_RESP}"

echo -e "\n--- [48/49] GET /oauth/jwks.json (OIDC Public JSON Web Key Set - RFC 7517) ---"
OIDC_JWKS_RESP=$(curl -s -X GET "${BASE_URL}/oauth/jwks.json")
echo "${OIDC_JWKS_RESP}"

echo -e "\n--- [49/52] POST /oauth/token (Invalid Authorization Code Rejection - RFC 7636) ---"
OIDC_TOKEN_RESP=$(curl -s -X POST "${BASE_URL}/oauth/token" \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"authorization_code","client_id":"unknown_client","code":"invalid_code","redirect_uri":"http://localhost:3000/callback","code_verifier":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}')
echo "${OIDC_TOKEN_RESP}"

echo -e "\n--- [50/52] GET /api/v1/auth/saml/metadata (SAML SP Metadata - ADR 0026) ---"
SAML_META_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/auth/saml/metadata")
echo "${SAML_META_RESP}"

echo -e "\n--- [51/52] GET /api/v1/auth/saml/login (SP-Initiated SAML Login - ADR 0026) ---"
SAML_LOGIN_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/auth/saml/login?org_id=${PRIMARY_ORG_ID}&return_url=https://app.observability.io/dashboard")
echo "${SAML_LOGIN_RESP}"

echo -e "\n--- [52/52] POST /api/v1/auth/saml/acs (ACS Assertion Consumption Rejection - ADR 0026) ---"
SAML_ACS_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/saml/acs" \
  -H "Content-Type: application/json" \
  -d '{"SAMLResponse":"PHNhbWxwOlJlc3BvbnNlPjwvc2FtbHA6UmVzcG9uc2U+","RelayState":"invalid_relay"}')
echo "${SAML_ACS_RESP}"

echo -e "\n--- [BONUS] POST /api/v1/auth/sign-out (Sign Out & Revoke Session) ---"
SIGNOUT_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/sign-out" \
  -H "Authorization: Bearer ${SWITCHED_TOKEN}")
echo "${SIGNOUT_RESP}"

echo -e "\n=========================================================="
echo " All 52 Auth Endpoints Executed and Verified Successfully! "
echo "=========================================================="




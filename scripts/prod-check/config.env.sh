#!/usr/bin/env bash

export AUTH_URL="${AUTH_URL:-http://localhost:3001}"

export TOKEN="${TOKEN:-YOUR_JWT_SESSION_TOKEN_HERE}"
export RESET_TOKEN="${RESET_TOKEN:-sample-reset-token}"
export API_KEY="${API_KEY:-YOUR_API_KEY_STRING_HERE}"

export X_REQUEST_ID="${X_REQUEST_ID:-req-$(date +%s)-12345}"
export X_CORRELATION_ID="${X_CORRELATION_ID:-corr-$(date +%s)-67890}"
export X_TENANT_ID="${X_TENANT_ID:-tenant-acme-corp}"
export TRACEPARENT="${TRACEPARENT:-00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01}"
export TRACESTATE="${TRACESTATE:-rojo=1,congo=2}"

export X_FORWARDED_FOR="${X_FORWARDED_FOR:-127.0.0.1}"
export USER_AGENT="${USER_AGENT:-Mozilla/5.0 (prod-check-curl-runner)}"
export X_CSRF_TOKEN="${X_CSRF_TOKEN:-csrf-token-sample-98765}"

export EMAIL="${EMAIL:-admin@example.com}"
export PASSWORD="${PASSWORD:-Password123!@#}"
export DEFAULT_PASSWORD="${DEFAULT_PASSWORD:-${PASSWORD}}"
export NEW_PASSWORD="${NEW_PASSWORD:-NewPassword123!@#}"
export DEFAULT_NEW_PASSWORD="${DEFAULT_NEW_PASSWORD:-${NEW_PASSWORD}}"
export CURRENT_PASSWORD="${CURRENT_PASSWORD:-${PASSWORD}}"
export NAME="${NAME:-Admin User}"
export ORG_NAME="${ORG_NAME:-Acme Corp}"
export ORG_SLUG="${ORG_SLUG:-acme-corp}"
export ROLE="${ROLE:-admin}"

export INVITE_EMAIL="${INVITE_EMAIL:-member@example.com}"
export INVITE_ROLE="${INVITE_ROLE:-member}"
export BLOCK_REASON="${BLOCK_REASON:-Security compliance policy enforcement}"

export ORG_ID="${ORG_ID:-${TARGET_ORG_ID:-target-org-id}}"
export TARGET_ORG_ID="${TARGET_ORG_ID:-${ORG_ID:-target-org-id}}"

export USER_ID="${USER_ID:-${TARGET_USER_ID:-target-user-id}}"
export TARGET_USER_ID="${TARGET_USER_ID:-${USER_ID:-target-user-id}}"

export KEY_ID="${KEY_ID:-${TARGET_KEY_ID:-target-key-id}}"
export TARGET_KEY_ID="${TARGET_KEY_ID:-${KEY_ID:-target-key-id}}"

export KEY_NAME="${KEY_NAME:-Production Ingestion Key}"
export KEY_TYPE="${KEY_TYPE:-general}"
export EXPIRES_IN_DAYS="${EXPIRES_IN_DAYS:-30}"
export EXPIRES_AT_MS="${EXPIRES_AT_MS:-$(( $(date +%s%3N) + EXPIRES_IN_DAYS * 86400000 ))}"
export REQUIRED_PERMISSION="${REQUIRED_PERMISSION:-traces:read}"
export PERMISSIONS="${PERMISSIONS:-[\"traces:read\",\"traces:write\"]}"

export VERIFICATION_TOKEN="${VERIFICATION_TOKEN:-sample-verification-token}"
export MAILER_PROVIDER="${MAILER_PROVIDER:-mock}"
export MAILER_FROM="${MAILER_FROM:-noreply@auth.local}"

export PAGE="${PAGE:-1}"
export LIMIT="${LIMIT:-20}"
export SEARCH="${SEARCH:-}"

export AUDIT_EVENT_TYPE="${AUDIT_EVENT_TYPE:-USER_SIGNIN}"
export AUDIT_FROM="${AUDIT_FROM:-2026-01-01T00:00:00Z}"
export AUDIT_TO="${AUDIT_TO:-2026-12-31T23:59:59Z}"
export AUDIT_LIMIT="${AUDIT_LIMIT:-50}"
export AUDIT_PAGE="${AUDIT_PAGE:-1}"

# Break-Glass Emergency
export INCIDENT_TICKET_ID="${INCIDENT_TICKET_ID:-INC-8899}"
export BREAK_GLASS_JUSTIFICATION="${BREAK_GLASS_JUSTIFICATION:-Emergency database dead-lock mitigation requiring elevated root privileges}"
export BREAK_GLASS_DURATION="${BREAK_GLASS_DURATION:-60}"
export BREAK_GLASS_SESSION_ID="${BREAK_GLASS_SESSION_ID:-sample-break-glass-session-id}"
export BREAK_GLASS_TERMINATE_REASON="${BREAK_GLASS_TERMINATE_REASON:-Emergency mitigation completed and incident closed}"

# MFA & Step-Up
export MFA_CODE="${MFA_CODE:-123456}"
export MFA_TOKEN="${MFA_TOKEN:-sample-mfa-token}"
export REAUTH_TOKEN="${REAUTH_TOKEN:-sample-reauth-token}"

# Honeytokens
export HONEYTOKEN_NAME="${HONEYTOKEN_NAME:-Canary API Key Prod}"
export HONEYTOKEN_ID="${HONEYTOKEN_ID:-sample-honeytoken-id}"

# WORM Immutable Audit
export WORM_SEGMENT_ID="${WORM_SEGMENT_ID:-seg-$(date +%s)}"
export WORM_ARCHIVE_ID="${WORM_ARCHIVE_ID:-sample-worm-archive-id}"

# Custom Roles & Permissions
export ROLE_NAME="${ROLE_NAME:-IncidentResponder}"
export ROLE_DESCRIPTION="${ROLE_DESCRIPTION:-Custom role for handling emergency ops and telemetry}"
export ROLE_ID="${ROLE_ID:-sample-role-id}"

# Webhooks
export WEBHOOK_URL="${WEBHOOK_URL:-https://webhook.site/sample-auth-receiver}"
export WEBHOOK_SUBSCRIPTION_ID="${WEBHOOK_SUBSCRIPTION_ID:-sample-webhook-sub-id}"

# Domains
export CLAIM_DOMAIN="${CLAIM_DOMAIN:-acme-corp.com}"
export DOMAIN_ID="${DOMAIN_ID:-sample-domain-id}"
export BLOCKED_DOMAIN="${BLOCKED_DOMAIN:-malicious-temp-mail.com}"

# Policies (ReBAC)
export POLICY_OBJECT="${POLICY_OBJECT:-org:org_enterprise_1}"
export POLICY_RELATION="${POLICY_RELATION:-member}"
export POLICY_SUBJECT="${POLICY_SUBJECT:-user:usr_sec_1}"

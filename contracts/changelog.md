# Auth Contracts Changelog

## [1.7.0] - 2026-10-15
### Added
- Organization Domain Claiming & Verified Auto-Join (DNS TXT + Email Gate) (ADR 0021):
  - Added `POST /api/v1/auth/domains`: Register pending domain claim for organization with cryptographic challenge token.
  - Added `GET /api/v1/auth/domains`: Enumerate claimed domains for tenant.
  - Added `POST /api/v1/auth/domains/{domainId}/verify`: Execute immediate on-demand DNS TXT challenge verification.
  - Added `PATCH /api/v1/auth/domains/{domainId}`: Modify domain auto-join settings and default member onboarding role.
  - Added `DELETE /api/v1/auth/domains/{domainId}`: Revoke domain claim ownership.
  - Added schema `ClaimedDomainRecord`.

## [1.6.0] - 2026-10-15
### Added
- Federated Identity Provider (OAuth 2.0 / OIDC) Single Sign-On & Account Linking:
  - Added `GET /api/v1/auth/oauth/{provider}/authorize`: Generate signed OAuth authorization URI and state.
  - Added `POST /api/v1/auth/oauth/{provider}/callback`: Exchange code and state for authenticated session tokens and account provisioning.
  - Added `GET /api/v1/auth/oauth/identities`: Enumerate linked OAuth provider identities for authenticated user.
  - Added `DELETE /api/v1/auth/oauth/identities/{provider}`: Unlink federated identity provider with account lockout prevention guard.

## [1.5.0] - 2026-10-14
### Added
- Multi-Device Session Management & Remote Kill (OWASP ASVS 3.3):
  - Added `GET /api/v1/auth/sessions`: List active concurrent sessions and devices for the authenticated user, indicating caller's current session via `is_current: true`.
  - Added `DELETE /api/v1/auth/sessions/{id}`: Terminate a specific remote session family by unique ID.
  - Added `DELETE /api/v1/auth/sessions`: Bulk terminate all other active remote sessions while immunizing the caller's active device session.
  - Added component schema `UserSessionSummary`.

## [1.4.0] - 2026-10-14
### Added
- GDPR Article 15 Data Subject Access Request (DSAR) JSON Export:
  - Added `GET /api/v1/auth/users/me/export` requiring Bearer user authentication.
  - Returns `StandardApiResponse` containing machine-readable export of user identity, organization memberships, API keys metadata, MFA enrollment status, and historical audit events with zero credential leakage.

## [1.3.0] - 2026-10-14
### Added
- Automated & Manual 30-Day Cascade Soft-Delete Purge (GDPR Article 17):
  - Documented `POST /api/v1/auth/admin/purge-expired` endpoint requiring Bearer admin authentication and RFC 9470 Step-Up Authentication (`X-Reauth-Token`).
  - Returns `StandardApiResponse` with total purged records count and duration telemetry.

## [1.2.0] - 2026-10-14
### Added
- Breached Password Screening (NIST SP 800-63B k-Anonymity):
  - Documented `HTTP 400 Bad Request` with canonical error code `PASSWORD_BREACHED` for candidate passwords appearing in public breach dumps.
  - Enforced across `POST /api/v1/auth/sign-up`, `POST /api/v1/auth/reset-password`, and `POST /api/v1/auth/change-password`.

## [1.1.0] - 2026-09-19

### Added
- OpenAPI 3.0 endpoints for Email Verification:
  - `POST /api/v1/auth/verify-email`: Single-use cryptographic token verification.
  - `POST /api/v1/auth/resend-verification`: Dispatches fresh verification token via configured transactional mailer.
- API Key Engine TTL & Expiration Enforcement:
  - Mandatory `expires_at_ms` in `CreateApiKeyRequest` for `super_secret` (`ak_sec_`) keys with max 90-day TTL.
  - Expiration enforcement on `POST /api/v1/auth/api-keys/verify` returning `401 Unauthorized` with `API_KEY_EXPIRED`.
- API Key Instant Revocation & Edge Denylist:
  - Revocation propagation to Redis edge denylist (`auth:revoked_api_key:{id}`).
  - Instant rejection of revoked keys returning `401 Unauthorized` with `API_KEY_REVOKED`.
- Usage Telemetry:
  - Track `last_used_at_ms` and `last_used_ip` on verified API key records.
- Component Schemas:
  - `VerifyEmailRequest`, `ResendVerificationRequest`, `ApiKeyRecord`.

## [1.0.0] - 2026-08-16
### Added
- Initial OpenAPI 3.0 specification for authentication, session validation, RBAC context propagation, and API key management.

# Auth Contracts Changelog

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

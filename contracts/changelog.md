# Auth Contracts Changelog

## [1.13.0] - 2026-10-15
### Added
- Zero-Trust API Key IP/CIDR Subnet Allowlists & Sliding Rate Quotas (ADR 0027):
  - Added `GET /api/v1/auth/api-keys/{id}/allowlist`: Retrieves IP/CIDR allowlist, rate quota, and anomaly flag metadata.
  - Added `PATCH /api/v1/auth/api-keys/{id}/allowlist`: Replaces IP allowlist CIDR array for key.
  - Added schema `UpdateApiKeyAllowlistRequest`.
  - Added `ip_allowlist` and `rate_quota_rpm` properties to `CreateApiKeyRequest`.
  - Added `client_ip` property to `VerifyApiKeyRequest`.
  - Added error status codes `403` (`API_KEY_IP_DENIED`) and `429` (`API_KEY_RATE_LIMIT_EXCEEDED`) to `POST /api/v1/auth/api-keys/verify`.

## [1.12.0] - 2026-10-15
### Added
- SAML 2.0 Enterprise Identity Provider & Service Provider Federation (ADR 0026):
  - Added `GET /api/v1/auth/saml/metadata`: SP EntityDescriptor XML with X.509 assertion signing expectations and ACS bindings.
  - Added `GET /api/v1/auth/saml/login`: SP-initiated SSO login returning AuthNRequest and cryptographically signed RelayState.
  - Added `POST /api/v1/auth/saml/acs`: Assertion Consumer Service verifying XMLDSig signatures, clock skew, and replay rejection.
  - Added `POST /api/v1/auth/saml/providers`: Registers enterprise SAML 2.0 Identity Provider.
  - Added `GET /api/v1/auth/saml/providers`: Lists registered SAML providers for an organization.
  - Added schema `SamlProviderRegistrationRequest`.

## [1.11.0] - 2026-10-15
### Added
- OpenID Connect (OIDC) Identity Provider & Discovery Core (RFC 8414 / RFC 7636 / RFC 7517 / ADR 0025):
  - Added `GET /.well-known/openid-configuration`: Standard OpenID Connect discovery metadata document.
  - Added `GET /oauth/jwks.json`: Public JSON Web Key Set for asymmetric RS256 token verification.
  - Added `GET /oauth/authorize`: Authorization code issuance endpoint with mandatory PKCE (`code_challenge_method = S256`) and strict redirect URI matching.
  - Added `POST /oauth/token`: Authorization code exchange returning asymmetric RS256 signed ID Tokens and Access Tokens.
  - Added `GET /oauth/userinfo`: Standard OIDC claims endpoint returning user profile and email claims.

## [1.10.0] - 2026-10-15

### Added
- SCIM 2.0 User & Group Provisioning API (RFC 7643 / RFC 7644 / ADR 0024):
  - Added `GET /scim/v2/ServiceProviderConfig`: Discovers SCIM service provider capabilities, supported filters, and authentication schemes.
  - Added `POST /scim/v2/Users`: Provisions enterprise employee from Okta / Entra ID with `externalId` mapping.
  - Added `GET /scim/v2/Users`: Filters and enumerates users via SCIM filter syntax (`userName eq "..."`).
  - Added `GET /scim/v2/Users/{id}`: Retrieves SCIM user record.
  - Added `PATCH /scim/v2/Users/{id}`: RFC 7644 patch operations (`active: false` deprovisions user and blocks access).
  - Added `DELETE /scim/v2/Users/{id}`: Deprovisions user from tenant organization.
  - Added `POST /scim/v2/Groups`: Creates SCIM team group with initial membership.
  - Added `GET /scim/v2/Groups`: Lists directory groups.
  - Added `GET /scim/v2/Groups/{id}`: Retrieves SCIM group by ID.
  - Added `PATCH /scim/v2/Groups/{id}`: Differential membership sync (`add` / `remove` members).
  - Added `DELETE /scim/v2/Groups/{id}`: Deletes SCIM group.

## [1.9.0] - 2026-10-15
### Added
- Fine-Grained Policy Engine (ABAC / ReBAC) with Zanzibar-Style Relationship Tuples (ADR 0023):
  - Added `POST /api/v1/auth/policies/evaluate`: Deterministic evaluation of permissions with transitive relation inheritance and ABAC conditions.
  - Added `POST /api/v1/auth/policies/relations`: Creates 6-ary relationship tuple `(org_id, subject_type, subject_id, relation, object_type, object_id)`.
  - Added `DELETE /api/v1/auth/policies/relations`: Revokes relationship tuple.
  - Added `GET /api/v1/auth/policies/relations`: Enumerates active relationship tuples filtered by subject or object.
  - Added schemas `RelationTuple`, `PolicyEvaluationRequest`, and `PolicyEvaluationResult`.

## [1.8.0] - 2026-10-15
### Added
- Unified Adaptive Risk-Based Authentication & Soft Step-Up (NIST SP 800-63-3 / ADR 0022):
  - Dynamic risk scoring pipeline ($0 - 100$) integrating ASN proxy intelligence (+40), Great-Circle Haversine velocity anomalies >900 km/h (+35), and browser fingerprint shifts (+25).
  - Added `POST /api/v1/auth/challenge/resolve`: Resolves ephemeral HMAC-SHA256 risk challenge tokens with single-use verification codes without terminating sessions.
  - Soft step-up challenge envelope (`status: "step_up_required"`, `risk_score`, `challenge_token`) for medium risk ($30 \le R < 75$).
  - High-risk denial envelope (`HTTP 403 Forbidden` / `HIGH_RISK_SIGNIN_BLOCKED`) for severe velocity/proxy anomalies ($R \ge 75$).

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

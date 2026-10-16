# 📋 Keycloak Migration & Technical Debt Reduction Roadmap (TODO-KEYCLOAK.md)

*An in-depth, phased architectural roadmap to migrate `@observability/auth` from a hand-rolled IAM engine to Keycloak, and purge dead, duplicated, and redundant code.*

---

## 📊 1. Master Migration & Deletion Matrix

> **Action Types**:
> - 🔴 **DELETE**: Completely remove code/tables rendered obsolete by Keycloak.
> - 🟡 **REFACTOR**: Simplify to integrate with Keycloak (e.g., replace custom logic with Keycloak JWT/JWKS verification).
> - 🟢 **RETAIN**: Keep as core application-level domain capabilities (API Keys, Tenant Org hierarchy, App ReBAC, Honeytokens).

| Subsystem / Area | Component File(s) | Keycloak Replacement | Action | Impact / Savings |
|---|---|---|---|---|
| **Social / OAuth Identity** | `oauth.service.ts`, `oauth.handler.ts`, Google/GitHub adapters | Keycloak Identity Brokering & Social Logins | 🔴 **DELETE** | ~600 LOC removed |
| **OIDC Identity Provider** | `oidc-provider.service.ts`, `oidc.handler.ts`, `oidc.config.ts` | Keycloak Native OpenID Connect Provider | 🔴 **DELETE** | ~600 LOC removed |
| **SAML 2.0 SP Federation** | `saml-provider.service.ts`, `saml.handler.ts`, `saml.config.ts`, `saml-xml.builder.ts` | Keycloak SAML 2.0 Identity Provider | 🔴 **DELETE** | ~600 LOC removed |
| **SCIM 2.0 Directory Sync** | `scim-provisioning.service.ts`, `scim.handler.ts`, SCIM ports | Keycloak User Federation / LDAP / SCIM plugins | 🔴 **DELETE** | ~400 LOC removed |
| **Password & Credential Lifecycle** | `password.service.ts`, `password.handler.ts`, `argon2.util.ts`, `pwned-passwords.adapter.ts` | Keycloak Credential Policy & Brute Force | 🔴 **DELETE** | ~450 LOC removed |
| **MFA & Recovery Codes** | `mfa.service.ts`, `mfa.handler.ts`, `totp-mfa.adapter.ts` | Keycloak TOTP & WebAuthn / OTP Flows | 🔴 **DELETE** | ~350 LOC removed |
| **Passkeys / WebAuthn** | `passkey.service.ts`, `passkey.handler.ts` | Keycloak WebAuthn Passkeys Authenticator | 🔴 **DELETE** | ~400 LOC removed |
| **Magic Link Passwordless** | `magic-link.service.ts`, `magic-link.handler.ts` | Keycloak Magic Link / OTP Action Tokens | 🔴 **DELETE** | ~300 LOC removed |
| **Session Invalidation & Denylist** | `session-denylist.service.ts`, `session.handler.ts`, Redis token denylist | Keycloak Backchannel Logout & Token Introspection | 🔴 **DELETE** | ~200 LOC removed |
| **Refresh Token Family Rotation** | `refresh-token.service.ts`, `auth_refresh_tokens` table | Keycloak Session & Token Refresh Engine | 🔴 **DELETE** | ~350 LOC removed |
| **Asymmetric Key Rotation** | `key-rotation.service.ts`, EdDSA key table | Keycloak Realm Keys (`/protocol/openid-connect/certs`) | 🔴 **DELETE** | ~300 LOC removed |
| **Login Rate Limiter & Shield** | `login-rate-limiter.service.ts`, `login-rate-limit.rules.ts` | Keycloak Brute Force & Rate Limiting | 🔴 **DELETE** | ~350 LOC removed |
| **Unused Workflow Engine** | `src/shared/workflow-engine/*`, `auth-provisioning.workflow.ts` | Dead code (0 runtime usages) | 🔴 **DELETE** | ~200 LOC removed |
| **Unused Declarative Rules Engine** | `src/shared/rules-engine/*` | Dead code (0 runtime usages) | 🔴 **DELETE** | ~200 LOC removed |
| **Unused Data-Driven Decorators** | `src/shared/data-driven/*` | Dead code (0 runtime usages) | 🔴 **DELETE** | ~250 LOC removed |
| **Unused Session State Machine** | `auth-session.machine.ts` | Dead code (0 runtime usages) | 🔴 **DELETE** | ~100 LOC removed |
| **Unused Proxy Stubs** | `src/infra/adapters/proxy/*` (`traefik.adapter.ts`, `envoy.adapter.ts`) | Dead code (0 runtime usages) | 🔴 **DELETE** | ~150 LOC removed |
| **Duplicate In-Memory DB Mock** | `alloydb-omni-auth.adapter.ts` | In-memory 1,438-line mock duplicating real adapter | 🔴 **DELETE / CONSOLIDATE** | ~1,438 LOC removed |
| **Session Verification Middleware** | `handleVerifySession` | Verifies JWT locally against Keycloak JWKS | 🟡 **REFACTOR** | Replace custom JWT decode with standard JWKS cache |
| **User Sign-up & Organization Binding** | `user-auth.service.ts`, `organization.service.ts` | Sync Keycloak `sub` ID to Org Tenant tables | 🟡 **REFACTOR** | Slim down to tenant context provider |
| **User Management API** | `user-management.service.ts` | Delegate user CRUD to Keycloak Admin REST API | 🟡 **REFACTOR** | Thin facade over Keycloak Admin Client |
| **Internal API Key Engine** | `api-key.service.ts`, `api-key.handler.ts`, CIDR / Quotas | None (App-specific M2M & CLI tokens) | 🟢 **RETAIN** | Keep core capability |
| **ReBAC Policy Engine** | `policy-engine.service.ts`, `policy.handler.ts` | None (Zanzibar granular graph authorization) | 🟢 **RETAIN** | Keep core capability |
| **Organization Tenant Management** | `organization.service.ts` (tenant switching & quotas) | None (Tenant isolation & metadata) | 🟢 **RETAIN** | Keep core capability |
| **Audit Log Subsystem** | `audit-log.service.ts` | None (Business-event audit compliance) | 🟢 **RETAIN** | Keep core capability |
| **Break-Glass Emergency Access** | `break-glass.service.ts`, `break-glass.handler.ts` | None (Specialized high-assurance SOC2 workflow) | 🟢 **RETAIN** | Keep core capability |
| **Honeytokens & Secret Scanning** | `honeytoken.service.ts`, `honeytoken.handler.ts` | None (Active defense canary token system) | 🟢 **RETAIN** | Keep core capability |

---

## 🎯 2. Migration Execution Phases

```mermaid
flowchart LR
    Phase0["Phase 0<br/>Dead Code Purge"] --> Phase1["Phase 1<br/>Keycloak Setup & Realm Config"]
    Phase1 --> Phase2["Phase 2<br/>JWKS Verifier Middleware"]
    Phase2 --> Phase3["Phase 3<br/>Service & Handler Deletion"]
    Phase3 --> Phase4["Phase 4<br/>DB Schema & Adapter Consolidation"]
    Phase4 --> Phase5["Phase 5<br/>E2E & Integration Verification"]
```

---

### Phase 0: Immediate Dead Code & Scaffolding Purge (Zero Risk)
Clean up code that is currently 100% unused by `src/server.ts` or any active HTTP request path.

- [ ] **Delete Unused Framework Stubs**:
  - [ ] Delete `src/shared/workflow-engine/runner.ts` and `step-registry.ts`.
  - [ ] Delete `src/features/auth/workflows/auth-provisioning.workflow.ts`.
  - [ ] Delete `src/shared/rules-engine/evaluator.ts` and `async-checkers.ts`.
  - [ ] Delete `src/shared/data-driven/` (`entity-schema.ts`, `json-map.ts`, `list-transform.ts`, `adapter-decorators.ts`).
  - [ ] Delete `src/features/auth/machines/auth-session.machine.ts`.
  - [ ] Delete `src/infra/adapters/proxy/` (`traefik.adapter.ts`, `envoy.adapter.ts`, `proxy.interface.ts`).
- [ ] **Clean Index Exports**:
  - [ ] Remove deleted file re-exports from `src/index.ts` and `src/features/auth/index.ts`.
- [ ] **Run Typecheck & Tests**:
  - [ ] Verify `npm run typecheck` and `npm test` continue passing.

---

### Phase 1: Keycloak Environment & Realm Architecture Setup
Deploy and configure Keycloak as the centralized Identity Provider.

- [ ] **Docker Compose & Deployment**:
  - [ ] Add `keycloak` service (Quarkus distribution) to `docker-compose.yml` backed by PostgreSQL.
  - [ ] Configure environment variables: `KEYCLOAK_ADMIN`, `KEYCLOAK_ADMIN_PASSWORD`, `KC_DB=postgres`, `KC_HTTP_ENABLED=true`.
- [ ] **Realm Configuration**:
  - [ ] Create realm `llm-observability`.
  - [ ] Create clients:
    - [ ] `frontend-web` (Public client, Authorization Code Flow with PKCE, Redirect URIs: `http://localhost:3000/*`).
    - [ ] `auth-service-admin` (Confidential client with Service Accounts enabled for Keycloak Admin REST API operations).
- [ ] **Identity Federation & Policies**:
  - [ ] Configure Social Identity Providers in Keycloak (Google, GitHub, GitLab) under Realm Identity Providers.
  - [ ] Set up Password Policy in Keycloak (Minimum length, character classes, expire password, hash algorithm).
  - [ ] Enable MFA (TOTP, WebAuthn Passkeys) in Keycloak Authentication Flows.
- [ ] **Custom Claims & Mappers**:
  - [ ] Add Realm / Client Token Mappers to inject user attributes into access tokens:
    - [ ] `org_id` / `tenant_id`
    - [ ] `role` / `permissions`
    - [ ] `email_verified`

---

### Phase 2: Keycloak JWT Verification Middleware Implementation
Replace custom session verification with standard OpenID Connect JWT validation.

- [ ] **Keycloak JWT Verifier Adapter**:
  - [ ] Implement `KeycloakJwtVerifier` using standard JWKS caching library (`jose` or `@chief-strategist-j/shared-infra`).
  - [ ] Configure JWKS URL: `${KEYCLOAK_ISSUER_URL}/protocol/openid-connect/certs`.
  - [ ] Validate standard claims: `iss` (matches Keycloak realm URL), `aud`, `exp`, `nbf`.
  - [ ] Extract user identity (`sub`, `email`, `preferred_username`, `tenant_id`).
- [ ] **Integrate with `AuthRestV1Router`**:
  - [ ] Update `handleVerifySession` in `session.handler.ts` (or convert directly to route middleware) to validate Keycloak tokens.
  - [ ] Eliminate internal session denylist check in Redis for user sessions (rely on short-lived JWTs [5m TTL] + Keycloak token revocation).

---

### Phase 3: Purge Redundant IAM Services & REST Handlers
Remove custom IAM handlers and services that are now fully delegated to Keycloak.

- [ ] **Delete Obsolete Domain Services (`src/features/auth/services/`)**:
  - [ ] `oidc-provider.service.ts`
  - [ ] `saml-provider.service.ts`
  - [ ] `oauth.service.ts`
  - [ ] `scim-provisioning.service.ts`
  - [ ] `password.service.ts`
  - [ ] `mfa.service.ts`
  - [ ] `passkey.service.ts`
  - [ ] `magic-link.service.ts`
  - [ ] `key-rotation.service.ts`
  - [ ] `refresh-token.service.ts`
  - [ ] `login-rate-limiter.service.ts`
  - [ ] `session-denylist.service.ts`
- [ ] **Delete Obsolete REST Handlers (`src/api/rest/v1/handlers/`)**:
  - [ ] `oidc.handler.ts`
  - [ ] `saml.handler.ts`
  - [ ] `oauth.handler.ts`
  - [ ] `scim.handler.ts`
  - [ ] `password.handler.ts`
  - [ ] `mfa.handler.ts`
  - [ ] `passkey.handler.ts`
  - [ ] `magic-link.handler.ts`
  - [ ] `email-verification.handler.ts`
- [ ] **Delete Obsolete Infrastructure Adapters (`src/infra/adapters/`)**:
  - [ ] `src/infra/adapters/mfa/totp-mfa.adapter.ts`
  - [ ] `src/infra/adapters/security/pwned-passwords.adapter.ts`
  - [ ] `src/infra/adapters/oauth/google-oauth.adapter.ts`
  - [ ] `src/infra/adapters/oauth/github-oauth.adapter.ts`
- [ ] **Prune `route.rules.ts` & `router.ts`**:
  - [ ] Remove routes for: `/api/v1/auth/sign-in`, `/sign-up`, `/password/*`, `/mfa/*`, `/passkeys/*`, `/magic-link/*`, `/oauth/*`, `/saml/*`, `/scim/v2/*`, `/.well-known/jwks.json`.
  - [ ] Retain routes for: `/api/v1/auth/organizations/*`, `/api/v1/auth/api-keys/*`, `/api/v1/auth/policy/*`, `/api/v1/auth/audit-logs/*`, `/api/v1/auth/break-glass/*`, `/api/v1/auth/honeytokens/*`.

---

### Phase 4: Database Schema Pruning & Adapter Consolidation
Clean up database tables and remove the duplicate in-memory mock repository adapter.

- [ ] **Consolidate Repository Adapters**:
  - [ ] Retire `AlloyDBOmniAuthAdapter` (1,438 lines of in-memory Maps).
  - [ ] Standardize strictly on `RealPostgresAuthAdapter` for both test and production (using lightweight transactional rollback or testcontainers for unit/integration tests).
  - [ ] Remove obsolete method interfaces from `AuthRepositoryPort` (`saveSaml*`, `saveScim*`, `savePasskey*`, `saveRefreshToken*`, `savePasswordHistory*`).
- [ ] **Create Database Rollback / Pruning Migration**:
  - [ ] Drop obsolete tables:
    - [ ] `auth_refresh_tokens`, `auth_refresh_token_families` (Migration 0010, 0012)
    - [ ] `auth_password_history` (Migration 0022)
    - [ ] `auth_passkeys` (Migration 0023)
    - [ ] `auth_magic_links` (Migration 0025)
    - [ ] `auth_saml_*` (Migration 0020)
    - [ ] `auth_scim_*` (Migration 0018)
    - [ ] `auth_oidc_*` (Migration 0019)
    - [ ] `auth_recovery_codes`, `auth_mfa` (Migration 0009)
    - [ ] `email_verifications` (Migration 0008)
    - [ ] `token_denylist` (Migration 0005)
  - [ ] Retain essential application tables:
    - [ ] `organizations`, `organization_users` (Tenant mapping)
    - [ ] `auth_users` (Application user profile metadata linked by Keycloak `sub`)
    - [ ] `api_keys` (Internal API Key Subsystem)
    - [ ] `auth_policies`, `auth_relations` (ReBAC Engine)
    - [ ] `auth_audit_logs` (Audit logging)
    - [ ] `auth_break_glass_sessions` (Break-glass emergency)
    - [ ] `auth_honeytokens` (Canary detection)

---

### Phase 5: Keycloak Admin Integration & Verification
Connect the auth service to Keycloak's Admin API for organization provisioning and user syncing.

- [ ] **Keycloak Admin Client Integration**:
  - [ ] Implement `KeycloakAdminAdapter` using `@keycloak/keycloak-admin-client`.
  - [ ] Implement user invite & disable flows:
    - [ ] `inviteUser`: Creates user in Keycloak with `sendEmail: true` and action `UPDATE_PASSWORD`.
    - [ ] `blockUser` / `unblockUser`: Toggles `enabled: false / true` in Keycloak.
    - [ ] `deleteUser`: Soft-deletes in application DB and deactivates in Keycloak.
- [ ] **Tenant / Organization Provisioning Workflow**:
  - [ ] When an organization is created in `@observability/auth`, create corresponding Keycloak User Group or Realm Role.
- [ ] **Test Suite Migration**:
  - [ ] Refactor integration tests to mock Keycloak JWKS tokens.
  - [ ] Verify complete API test suite passes: `npm run typecheck` and `npm test`.

---

## 📈 3. Target Architecture Comparison

| Metric | Before (Current Hand-Rolled IAM) | After (With Keycloak) |
|---|---|---|
| **Source Code Size** | ~192 files / ~25,000 LOC | ~40 files / ~5,000 LOC (**-80% code reduction**) |
| **Security Surface Area** | Must maintain custom crypto, hashing, SAML XML parsing, and Passkey WebAuthn | Delegated to CNCF/RedHat hardened Keycloak container |
| **Database Migrations** | 34 migrations across 25+ auth tables | ~8 tables focused purely on application tenancy & policies |
| **Authentication Standards** | Incomplete custom OIDC/SAML/SCIM compliance | Full certified OpenID Connect, OAuth2, and SAML 2.0 compliance |
| **Developer Maintenance** | High: bugs in password reset, token rotation, and MFA require in-house patches | Low: off-the-shelf Keycloak updates handle CVEs and compliance |

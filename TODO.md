# 📋 Auth Module Feature Roadmap & Security Specification

*A comprehensive enterprise engineering roadmap, security specification, and architectural backlog for `@observability/auth`.*

---

## 📊 1. Master Feature Implementation Matrix (Prioritized Sequencing)

> **Priority Tier Definitions**:
> - **P0 (Critical Live Production Blocker)**: Existing gaps in live v1.0 that present active security or operational risk.
> - **P1 (Immediate Milestone v1.1)**: Core security hardening, credential lifecycle, and compliance requirements.
> - **P2 (Scaled Enterprise v1.2)**: Advanced authentication primitives, adaptive risk heuristics, and session controls.
> - **P3 (Federation & Architecture v1.3+)**: Enterprise directory federation, graph authorization, and zero-trust infrastructure.

| Domain | Capability | RFC / Standard | Current Status | Milestone | Priority |
|---|---|---|---|---|---|
| **Security & Defense** | Step-Up Authentication for High-Value Actions (incl. Impersonation) | RFC 9470 | ✅ **Completed (ADR 0013)** | v1.1 | **P1** |
| **Session Management** | Refresh Token Rotation & Family Reuse Detection | RFC 6749 §10.4 | ✅ **Completed (ADR 0014)** | v1.1 | **P1** |
| **Core Authentication** | Breached Password Screening (HaveIBeenPwned k-Anonymity) | NIST SP 800-63B | ✅ **Completed (ADR 0015)** | v1.1 | **P1** |
| **User Lifecycle** | Automated 30-Day Cascade Soft-Delete Purge Cron Worker | GDPR Article 17 | ✅ **Completed (ADR 0016)** | v1.1 | **P1** |

| **Audit & Compliance** | GDPR Data Subject Access Request (DSAR) JSON Export | GDPR Article 15 | ✅ **Completed (ADR 0017)** | v1.1 | **P1** |
| **Security & Defense** | Automated Security Headers & Strict CSP (Nonces) | W3C CSP Level 3 | ✅ **Completed (ADR 0018)** | v1.1 | **P1** |
| **Enterprise Identity** | OAuth2 / OIDC Social Login (Google, GitHub, GitLab) | RFC 6749 / OIDC | ⏳ **Pending** | v1.1 | **P1** |
| **Core Authentication** | WebAuthn / FIDO2 Passkeys (Biometrics & Hardware Keys) | W3C WebAuthn L3 | ⏳ **Pending** | v1.2 | **P2** |
| **Session Management** | Multi-Device Session Listing & Remote Kill | OWASP ASVS 3.3 | ⏳ **Pending** | v1.2 | **P2** |
| **Security & Defense** | Unified Adaptive Risk-Based Authentication (Soft Step-Up) | NIST SP 800-63-3 | ⏳ **Pending** | v1.2 | **P2** |
| **Enterprise Identity** | Organization Domain Claiming & Verified Auto-Join | DNS TXT + Email Gate | ⏳ **Pending** | v1.2 | **P2** |
| **API Key Engine** | IP / CIDR Subnet Allowlist & Usage Analytics Telemetry | Zero-Trust Network | ⏳ **Pending** | v1.2 | **P2** |
| **Access Control (RBAC/ABAC)** | Custom Enterprise Roles & 64-bit Permission Bitmasks | Granular Bitmask Engine | ⏳ **Pending** | v1.2 | **P2** |
| **User Lifecycle** | Password History Enforcement (Disallow Prior 10 Passwords) | NIST SP 800-63B | ⏳ **Pending** | v1.2 | **P2** |
| **Core Authentication** | Magic Link / Passwordless Authentication Flow | RFC 7519 | ⏳ **Pending** | v1.2 | **P2** |
| **Security & Defense** | Anti-Homoglyph & Unicode Normalization Shield | Unicode TR39 / NFKC | ⏳ **Pending** | v1.2 | **P2** |
| **Security & Defense** | Webhook Cryptographic Signatures & Anti-Replay Nonces | RFC 2104 HMAC-SHA256 | ⏳ **Pending** | v1.2 | **P2** |
| **Enterprise Identity** | Full OAuth 2.0 / OIDC Identity Provider (Auth Code + PKCE) | RFC 7636 / RFC 6749 | ⏳ **Pending** | v1.3 | **P3** |
| **Enterprise Identity** | SCIM 2.0 Automated User & Group Directory Provisioning | RFC 7643 / RFC 7644 | ⏳ **Pending** | v1.3 | **P3** |
| **Enterprise Identity** | Enterprise SAML 2.0 Service Provider Federation | SAML 2.0 Core | ⏳ **Pending** | v1.3 | **P3** |
| **Enterprise Identity** | Machine-to-Machine (M2M) Client Credentials Grant | RFC 6749 §4.4 | ⏳ **Pending** | v1.3 | **P3** |
| **Session Management** | Standardized EdDSA (Ed25519) JWKS Key Rotation | RFC 8037 EdDSA | ⏳ **Pending** | v1.3 | **P3** |
| **Access Control (RBAC/ABAC)** | Relationship-Based Access Control (ReBAC / Zanzibar Graphs) | Google Zanzibar Model | ⏳ **Pending** | v1.3 | **P3** |
| **Access Control (RBAC/ABAC)** | Monitored Break-Glass Emergency Access Workflow | SOC 2 CC6.1 / CC6.2 | ⏳ **Pending** | v1.3 | **P3** |
| **Security & Defense** | Field-Level PII Envelope Encryption (AES-256-GCM / KMS) | NIST SP 800-38D | ⏳ **Pending** | v1.3 | **P3** |
| **Security & Defense** | Cryptographic Shredding (GDPR Art. 17 User DEKs) | GDPR Article 17 | ⏳ **Pending** | v1.3 | **P3** |
| **Security & Defense** | Distributed Credential Stuffing & ASN Velocity Defense | Threat Intelligence | ⏳ **Pending** | v1.3 | **P3** |
| **Security & Defense** | Mutual TLS (mTLS) Zero-Trust Microservice Authentication | RFC 8705 / TLS 1.3 | ⏳ **Pending** | v1.3 | **P3** |
| **Security & Defense** | Honeytokens & Active Canary Secret Scanning | Deception Technology | ⏳ **Pending** | v1.3 | **P3** |
| **Audit & Compliance** | Immutable WORM Audit Archive (S3 Object Lock / Glacier) | SEC Rule 17a-4(f) | ⏳ **Pending** | v1.3 | **P3** |
| **Developer Experience** | Database Seed Script (`npm run db:seed`) | Developer Fixtures | ⏳ **Pending** | v1.1 | **P1** |

---


## 🔐 3. Deep-Dive: Security-Related Features

### 3.1 Dual-Track Rate Limiting & Bot Defense
- **Vulnerability Addressed**: Distributed brute-force, password guessing, and automated account lockout DoS.
- **Specification**:
  - Redis sliding-window counter tracking `login_failures:ip:{subnet}` and `login_failures:email:{email_hash}`.
  - IP threshold: 10 failures in 10 minutes $\rightarrow$ `HTTP 429 Too Many Requests` (`Retry-After: 600`).
  - Email threshold: 3 failures in 15 minutes $\rightarrow$ subsequent requests require valid `cf-turnstile-response` header + 2-second progressive delay.

### 3.2 Breached Password Detection (HaveIBeenPwned k-Anonymity)
- **Vulnerability Addressed**: Credential stuffing using compromised passwords from public breaches.
- **Specification**:
  - On user sign-up and password update, compute SHA-1 of the candidate password.
  - Query HaveIBeenPwned API using **k-anonymity**: send only the first 5 characters of the SHA-1 hash (`GET https://api.pwnedpasswords.com/range/{prefix}`).
  - Match remainder locally. If the password appears in breach dumps, reject with `400 Bad Request`. Zero password material ever leaves the auth server.

### 3.3 Step-Up Authentication for High-Value Actions (RFC 9470)
- **Vulnerability Addressed**: Unauthorized execution of destructive actions via hijacked or abandoned sessions.
- **Protected Endpoints (Mandatory List)**:
  1. `POST /api/v1/auth/admin/impersonate/:user_id` (Account Takeover Guard)
  2. `DELETE /api/v1/auth/organizations/:id` (Organization Destruction)
  3. `POST /api/v1/auth/api-keys` with `tier: super_secret` (High-Privilege Credential Creation)
  4. `PATCH /api/v1/auth/users/:id/role` to `owner` or `admin` (Privilege Escalation)
  5. `POST /api/v1/auth/mfa/disable` (Security Control Downgrade)
- **Specification**:
  - Requires a fresh re-authentication token (`reauth_token`) generated within the last **300 seconds (5 minutes)** via password re-entry or WebAuthn biometric assertion.
  - If missing or expired, return `HTTP 403 Forbidden` with header `WWW-Authenticate: StepUp max_age=300`.

### 3.4 Unified Adaptive Risk-Based Authentication (Soft Step-Up)
- **Vulnerability Addressed**: Static authentication barriers that fail against targeted attacks, while avoiding false-positive session disruption for legitimate mobile and VPN users.
- **Design Decision**: Avoid hard session termination or hard `/24` subnet freezes for mobile CGNAT users. Network shifts must trigger a **soft step-up challenge** rather than an outright denial or session kill.
- **Specification**:
  - Calculate dynamic Risk Score $(0 - 100)$:
    - Known Datacenter/Proxy/Tor ASN: $+40$ risk.
    - Extreme Velocity ($>900\text{ km/h}$ between consecutive geographic locations): $+35$ risk.
    - Unrecognized Browser Fingerprint / User-Agent Shift: $+25$ risk.
  - **Action Thresholds**:
    - `Risk < 30`: Normal seamless access.
    - `30 <= Risk < 75`: Soft Step-Up Challenge (Prompts TOTP, WebAuthn passkey, or sends a 6-digit email confirmation code to verify identity).
    - `Risk >= 75`: Reject authentication with security notification dispatched to user and SIEM alert.

### 3.5 Field-Level PII Envelope Encryption (AES-256-GCM & KMS)
- **Vulnerability Addressed**: Cleartext data exposure during database backups or database dump leaks.
- **Storage Model Clarification**:
  - **Reversible Fields (Envelope Encrypted)**: `email`, `phone`, `mfa_secret` are encrypted using AES-256-GCM with Data Encryption Keys (DEKs) wrapped by a KMS Key Encryption Key (KEK).
  - **Irreversible Fields (Hashed Only)**: MFA recovery backup codes are stored as **salted SHA-256 hashes** (one-time burn on use). They are NEVER stored in reversible envelope encryption.
  - Blind indexes (HMAC-SHA256 with tenant salt) are used for exact-match database queries (`email_hash`).

### 3.6 Cryptographic Shredding & Right-To-Be-Forgotten (GDPR Art. 17)
- **Vulnerability Addressed**: Inability to purge PII from immutable database backups, write-ahead logs (WAL), and read replicas when honoring GDPR erasure requests.
- **Specification**:
  - Every user identity has a dedicated AES-256 Data Encryption Key (DEK) stored in an isolated secure Key Vault table.
  - All user PII is encrypted with their specific DEK.
  - Upon user deletion or GDPR Article 17 execution:
    - The user's DEK is securely wiped from the Key Vault with zeroized memory overwrite.
    - Historical database snapshots, read replicas, and WAL records become mathematically unrecoverable white noise immediately, guaranteeing compliance without mutating immutable audit archives.

### 3.7 Standardized Asymmetric EdDSA (Ed25519) JWKS Key Rotation
- **Design Decision**: Eliminate legacy dual-algorithm complexity. Standardize exclusively on **EdDSA (RFC 8037 curve Ed25519)** for all asymmetric token signing. Ed25519 provides superior cryptographic security, smaller signature sizes (64 bytes), immunity to timing attacks, and orders-of-magnitude faster verification than RSA-2048.
- **Specification**:
  - Publish public keys via `GET /.well-known/jwks.json` using `kty: "OKP"` and `crv: "Ed25519"`.
  - Maintain active and retirement key IDs (`kid`) to support scheduled zero-downtime key rotation.

### 3.8 Automated Security Headers & Strict Content Security Policy (CSP Nonces)
- **Vulnerability Addressed**: Cross-Site Scripting (XSS), Clickjacking, MIME-sniffing, and downgrade attacks.
- **Specification**:
  - Strict middleware injection on every HTTP response:
    - `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` (HSTS).
    - `X-Content-Type-Options: nosniff`.
    - `X-Frame-Options: DENY`.
    - `Referrer-Policy: strict-origin-when-cross-origin`.
    - `Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()`.
    - `Content-Security-Policy`: Dynamic cryptographically secure base64 nonce generated per request (`script-src 'nonce-{NONCE}' 'strict-dynamic'; object-src 'none'; base-uri 'none'`).

### 3.9 Anti-Homoglyph & Unicode Normalization Shield (NFKC / Confusable Detection)
- **Vulnerability Addressed**: Internationalized domain name (IDN) homograph attacks and Unicode evasion where an attacker registers visually identical email addresses (e.g. Cyrillic `а` vs Latin `a`) to hijack invites or spoof administrators.
- **Specification**:
  - Normalize all email and username inputs to Unicode Normalization Form KC (NFKC) before validation.
  - Implement Unicode Technical Report #39 (UTR 39) confusable string detection.
  - Reject email registrations containing mixed-script confusable characters targeting registered tenant domains or administrative accounts.

### 3.10 Webhook Cryptographic Signatures & Anti-Replay Nonces
- **Vulnerability Addressed**: Man-in-the-middle tampering, spoofed webhook payloads, and replay attacks on downstream consumers.
- **Specification**:
  - Every outbound webhook (`user.created`, `org.member_removed`, `security.lockout`) includes headers:
    - `X-Auth-Signature: t={timestamp},v1={hmac_sha256_hex}`.
    - `X-Auth-Nonce: {uuid_v4}`.
  - The signature is calculated over `t.{timestamp}.payload.{body}` using a tenant-specific shared secret.
  - Tolerance window: receivers reject webhooks where `|current_time - timestamp| > 300` seconds to guarantee anti-replay integrity.

---

## 🔑 4. Deep-Dive: Auth-Related Features

### 4.1 Multi-Factor Authentication (MFA / 2FA - RFC 6238 TOTP & Salted Recovery Codes)
- **Endpoints**:
  - `POST /api/v1/auth/mfa/setup`: Generates cryptographically secure base32 secret and `otpauth://` QR code URI.
  - `POST /api/v1/auth/mfa/verify`: Validates 6-digit TOTP code and activates MFA on the account.
  - `POST /api/v1/auth/mfa/recovery-codes`: Generates 10 single-use random recovery codes.
- **Storage Model**:
  - Recovery codes are hashed with **salted SHA-256** prior to database insertion (`auth_recovery_codes`).
  - Upon successful use, the specific recovery code row is permanently deleted (one-time burn).
- **Login Flow**:
  - On `POST /api/v1/auth/sign-in`, if `mfa_enabled === true`, return `HTTP 200 { status: "mfa_required", mfa_token: "..." }`.
  - Client calls `POST /api/v1/auth/mfa/challenge` with the TOTP code to exchange `mfa_token` for the final session JWT.

### 4.2 Refresh Token Rotation & Family Reuse Detection
- **Endpoints**:
  - `POST /api/v1/auth/refresh`: Exchanges valid refresh token for a fresh access token (15-minute TTL) and a new refresh token (7-day TTL).
- **Security Protections**:
  - Refresh tokens stored in `HttpOnly; Secure; SameSite=Lax` cookies.
  - **Token Family Reuse Detection**: Every refresh token belongs to a cryptographically linked family tree. If an already-used refresh token is presented, the system assumes token theft and immediately revokes the **entire token family**, invalidating all sessions for that user device across all nodes.

### 4.3 Super-Admin User Impersonation (Hardened Security Specification)
- **Vulnerability Addressed**: Uncontrolled, un-audited, or persistent administrative account takeovers.
- **Mandatory Security Controls**:
  1. **Step-Up Authentication Required**: Initiating `POST /api/v1/auth/admin/impersonate/:user_id` requires a fresh 5-minute `reauth_token`.
  2. **Strict Time-Boxing**: Impersonation sessions expire in maximum **900 seconds (15 minutes)**. The issued JWT cannot be refreshed.
  3. **Mandatory Target Notification**: An automated security alert is instantly dispatched to the target user's email: *"Security Notice: Administrator {admin_email} accessed your account under Support Ticket #{ticket_id}"*.
  4. **Strict Tenant Boundaries**: Organization Administrators can **only** impersonate users within their own organization. Cross-tenant impersonation is strictly restricted to platform Super-Admins with an external audit ticket ID.
  5. **Audit Metadata**: All actions performed under impersonation include audit attributes `{ impersonated_by: admin_user_id, ticket_id: "TICK-1234" }`.

### 4.4 Organization Domain Claiming & Email-Verified Auto-Join
- **Vulnerability Addressed**: Unauthorized self-assignment into corporate organizations without proving email ownership.
- **Specification**:
  - Enterprise organizations claim email domains (e.g. `acme.com`) via DNS TXT record verification.
  - **Email Verification Gate (Strict Requirement)**: When a new user registers with an `@acme.com` address, auto-join is **held in pending status**.
  - The user is only added to the corporate organization after **email ownership is cryptographically verified** via transactional email confirmation token or corporate SSO/SAML assertion.
  - Self-registered unverified accounts NEVER inherit organization membership.

### 4.5 Multi-Device Session Management
- **Endpoints**:
  - `GET /api/v1/auth/sessions`: Lists all active user sessions with metadata: IP address, location, browser, OS, login timestamp, last active timestamp, and `is_current` flag.
  - `DELETE /api/v1/auth/sessions/:session_id`: Revokes a specific remote device session.
  - `DELETE /api/v1/auth/sessions`: "Sign Out All Other Devices" button.

### 4.6 WebAuthn / FIDO2 Passkeys (Passwordless Biometric Authentication)
- **Specification**:
  - Implement W3C WebAuthn Level 3 specifications via `@simplewebauthn/server` enabling TouchID, FaceID, Windows Hello, and hardware security keys (YubiKey).
  - **Registration Endpoints**:
    - `POST /api/v1/auth/passkeys/register/start`: Generates cryptographic challenge, relying party ID (`rpId`), and supported algorithms (`EdDSA`, `ES256`).
    - `POST /api/v1/auth/passkeys/register/finish`: Verifies client attestation statement, stores public key credential, credential ID, and signature counter in `auth_passkeys`.
  - **Authentication Endpoints**:
    - `POST /api/v1/auth/passkeys/authenticate/start`: Emits authentication challenge.
    - `POST /api/v1/auth/passkeys/authenticate/finish`: Verifies cryptographic signature assertion against stored public key and checks counter to prevent cloned authenticator attacks.

### 4.7 Magic Link Authentication (Passwordless One-Time Links)
- **Specification**:
  - `POST /api/v1/auth/magic-link`: Accepts email, generates a cryptographically random 256-bit token stored in Redis with 10-minute TTL.
  - Formats link: `https://app.example.com/auth/verify-magic-link?token={TOKEN}` and sends via transactional email.
  - `POST /api/v1/auth/verify-magic-link`: Atomically validates and deletes token ($O(1)$ single-use guarantee in Redis via Lua script). Issues session JWT and refresh token cookies.

### 4.8 Full OAuth 2.0 / OIDC Identity Provider (Authorization Code + PKCE)
- **Specification**:
  - Enable `@observability/auth` to serve as a standards-compliant OAuth 2.0 Authorization Server and OpenID Connect (OIDC) Provider.
  - **Endpoints**:
    - `GET /.well-known/openid-configuration`: Discovery metadata document.
    - `GET /oauth/authorize`: Supports `response_type=code`, `scope=openid profile email`, `code_challenge`, and `code_challenge_method=S256` (RFC 7636 PKCE mandatory).
    - `POST /oauth/token`: Exchanges authorization code for ID token (JWT) and access token.
    - `GET /oauth/userinfo`: Returns standard OIDC user profile claims.

### 4.9 Machine-to-Machine (M2M) Service Accounts & Client Credentials Grant
- **Specification**:
  - Enterprise support for automated pipelines, external workers, and daemon microservices (RFC 6749 §4.4).
  - Admin provisions Service Account: assigns dedicated `client_id`, `client_secret` (stored as Argon2id hash), and specific scopes (e.g. `traces:write`, `metrics:read`).
  - Endpoint `POST /api/v1/auth/token` with `grant_type=client_credentials`: Validates credentials and returns scoped, short-lived (1-hour) bearer JWT without user identity context.

### 4.10 SCIM 2.0 Automated Enterprise Directory Provisioning (RFC 7643 & RFC 7644)
- **Specification**:
  - Enables enterprise Okta, Azure AD, or PingFederate directories to automatically provision, update, and deprovision employees in real-time.
  - **Endpoints**:
    - `GET /scim/v2/Users`: Filters and pages enterprise directory users.
    - `POST /scim/v2/Users`: Creates user upon employee hire.
    - `PUT/PATCH /scim/v2/Users/:id`: Updates roles, departments, and active status.
    - `DELETE /scim/v2/Users/:id`: Instantly suspends user access upon employee termination.
    - `GET /scim/v2/Groups`: Manages department team memberships.

### 4.11 Relationship-Based Access Control (ReBAC / Zanzibar Graphs)
- **Specification**:
  - Model complex hierarchical and relational permissions beyond flat RBAC (inspired by Google Zanzibar and OpenFGA).
  - Triplet store: `(subject, relation, object)` e.g.:
    - `user:42` is `member` of `team:core-infra`
    - `team:core-infra` is `editor` of `project:trace-pipeline`
    - `project:trace-pipeline` is `child_of` `organization:acme`
  - High-performance recursive graph resolution engine with in-memory memoization to resolve `check(subject, permission, resource)` in $<5\text{ms}$.

### 4.12 Enterprise SAML 2.0 Service Provider Federation
- **Specification**:
  - Comprehensive SAML 2.0 Service Provider (SP) implementation.
  - `GET /api/v1/auth/saml/metadata`: Publishes SP metadata XML with X.509 signing certificates.
  - `POST /api/v1/auth/saml/acs`: Assertion Consumer Service endpoint that decrypts and parses XML SAML Response from IdP, validates X.509 signatures, checks audience restriction and timestamp freshness, and provisions session.

### 4.13 Custom Enterprise Roles & Granular Permission Bitmasks
- **Specification**:
  - Allow enterprise organization owners to define custom roles beyond default roles (Owner, Admin, Member, Viewer).
  - Assign granular permissions encoded as 64-bit integer bitmasks for instant $O(1)$ bitwise evaluation (`user_bits & REQUIRED_PERM === REQUIRED_PERM`).

### 4.14 Password History Enforcement & Cyclic Reuse Prevention
- **Specification**:
  - Maintain historical password hash table `auth_password_history` storing the last 10 Argon2id password hashes for each user.
  - When changing or resetting password, verify candidate password against all previous 10 hashes.
  - If a match is detected, reject update with `400 Bad Request: "You cannot reuse any of your last 10 passwords."`.

### 4.15 Monitored Break-Glass Emergency Access Workflow
- **Specification**:
  - Highly auditable disaster recovery mechanism for enterprise outages when SSO or IdP is down (SOC 2 CC6.1 requirement).
  - Break-glass credentials secured with split-knowledge secret sharing (Shamir's Secret Sharing requiring $M$-of-$N$ executive approvals).
  - Invoking break-glass mode triggers immediate PagerDuty incident, sends SMS notifications to all organization administrators, and enables maximum-fidelity session recording and audit logging.

---

## 🛠 5. Compliance & Operational Sequencing

- [x] **Automated 30-Day Cascade Soft-Delete Purge Cron Worker (Promoted to P1 / v1.1 - Completed ADR 0016)**:
  - Eliminates the compliance timeline gap between soft-delete marking and physical record purging.
  - Runs nightly: hard-deletes user records and cascading dependencies where `deleted_at_ms < (now - 30 days)`.
  - Implemented `PurgeRetentionWorker` with distributed lease lock (`auth:lock:retention_purge`) and `POST /api/v1/auth/admin/purge-expired` endpoint.
- [ ] **GDPR DSAR JSON Export Endpoint (Promoted to P1 / v1.1)**:
  - Endpoint `GET /api/v1/auth/users/me/export` returning machine-readable JSON data archive satisfying GDPR Article 15 compliance.
- [ ] **Automated Database Seeder (`database/seeds/seed.ts`)**:
  - `npm run db:seed`: Populates standard local development fixtures (Default Organization, Admin, Viewer, pre-seeded API keys).
- [ ] **Prometheus Alert Rules for Authentication**:
  - High Failure Rate: Trigger alert if sign-in failure rate exceeds 5% over 5 minutes.
  - Brute Force Spikes: Alert if lockout events exceed 10 per minute.
  - High Latency: Alert if p95 authentication latency exceeds 300ms.

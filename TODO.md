# 📋 Auth Module Feature Roadmap & Security Specification

*A comprehensive enterprise engineering roadmap, security specification, and architectural backlog for `@observability/auth`.*

---

## 📊 1. Master Feature Implementation Matrix

> **Priority Tier Definitions**:
> - **P0 (Critical Live Production Blocker)**: Zero-day vulnerabilities or core service unavailability in live production.
> - **P1 (Immediate Core Hardening)**: Security baselines, credential lifecycle, regulatory compliance, and developer fixtures.
> - **P2 (Scaled Enterprise Security)**: Phishing-resistant authentication, adaptive risk heuristics, granular session and network controls.
> - **P3 (Enterprise Directory & Federation)**: B2B directory sync, graph-based access control, and cryptographic zero-trust infrastructure.

| Domain | Capability | RFC / Standard | Current Status | Milestone | Priority |
|---|---|---|---|---|---|
| **Security & Defense** | Step-Up Authentication for High-Value Actions (incl. Impersonation) | RFC 9470 | ✅ **Completed (ADR 0013)** | v1.1 | **P1** |
| **Session Management** | Refresh Token Rotation & Family Reuse Detection | RFC 6749 §10.4 | ✅ **Completed (ADR 0014)** | v1.1 | **P1** |
| **Core Authentication** | Breached Password Screening (HaveIBeenPwned k-Anonymity) | NIST SP 800-63B | ✅ **Completed (ADR 0015)** | v1.1 | **P1** |
| **User Lifecycle** | Automated 30-Day Cascade Soft-Delete Purge Cron Worker | GDPR Article 17 | ✅ **Completed (ADR 0016)** | v1.1 | **P1** |
| **Audit & Compliance** | GDPR Data Subject Access Request (DSAR) JSON Export | GDPR Article 15 | ✅ **Completed (ADR 0017)** | v1.1 | **P1** |
| **Security & Defense** | Automated Security Headers & Strict CSP (Nonces) | W3C CSP Level 3 | ✅ **Completed (ADR 0018)** | v1.1 | **P1** |
| **Enterprise Identity** | OAuth2 / OIDC Social Login (Google, GitHub, GitLab) | RFC 6749 / OIDC | ✅ **Completed (ADR 0020)** | v1.1 | **P1** |
| **Session Management** | Multi-Device Session Listing & Remote Kill | OWASP ASVS 3.3 | ✅ **Completed (ADR 0019)** | v1.2 | **P2** |
| **Enterprise Identity** | Organization Domain Claiming & Verified Auto-Join | DNS TXT + Email Gate | ✅ **Completed (ADR 0021)** | v1.2 | **P2** |
| **Security & Defense** | Unified Adaptive Risk-Based Authentication (Soft Step-Up) | NIST SP 800-63-3 | ✅ **Completed (ADR 0022)** | v1.2 | **P2** |
| **Access Control (RBAC/ABAC)** | Relationship-Based Access Control (ReBAC / Zanzibar Graphs) | Google Zanzibar Model | ✅ **Completed (ADR 0023)** | v1.3 | **P3** |
| **Enterprise Identity** | SCIM 2.0 Automated User & Group Directory Provisioning | RFC 7643 / RFC 7644 | ✅ **Completed (ADR 0024)** | v1.3 | **P3** |
| **Enterprise Identity** | Full OAuth 2.0 / OIDC Identity Provider (Auth Code + PKCE) | RFC 7636 / RFC 6749 | ✅ **Completed (ADR 0025)** | v1.3 | **P3** |
| **Enterprise Identity** | Enterprise SAML 2.0 Service Provider Federation | SAML 2.0 Core | ✅ **Completed (ADR 0026)** | v1.3 | **P3** |
| **API Key Engine** | IP / CIDR Subnet Allowlist & Usage Analytics Telemetry | Zero-Trust Network | ✅ **Completed (ADR 0027)** | v1.2 | **P2** |
| **User Lifecycle** | Password History Enforcement (Disallow Prior 10 Passwords) | NIST SP 800-63B | ✅ **Completed (ADR 0028)** | v1.2 | **P2** |
| **Core Authentication** | WebAuthn / FIDO2 Passkeys (Biometrics & Hardware Keys) | W3C WebAuthn L3 | ✅ **Completed (ADR 0029)** | v1.2 | **P2** |
| **Access Control (RBAC/ABAC)** | Custom Enterprise Roles & 64-bit Permission Bitmasks | Granular Bitmask Engine | ✅ **Completed (ADR 0030)** | v1.2 | **P2** |
| **Core Authentication** | Magic Link / Passwordless Authentication Flow | RFC 7519 | ✅ **Completed (ADR 0031)** | v1.2 | **P2** |
| **Security & Defense** | Anti-Homoglyph & Unicode Normalization Shield | Unicode TR39 / NFKC | ✅ **Completed (ADR 0032)** | v1.2 | **P2** |
| **Security & Defense** | Webhook Cryptographic Signatures & Anti-Replay Nonces | RFC 2104 HMAC-SHA256 | ✅ **Completed (ADR 0033)** | v1.2 | **P2** |
| **Enterprise Identity** | Machine-to-Machine (M2M) Client Credentials Grant | RFC 6749 §4.4 | ✅ **Completed (ADR 0034)** | v1.3 | **P3** |
| **Session Management** | Standardized EdDSA (Ed25519) JWKS Key Rotation | RFC 8037 EdDSA | ⏳ **Pending** | v1.3 | **P3** |
| **Access Control (RBAC/ABAC)** | Monitored Break-Glass Emergency Access Workflow | SOC 2 CC6.1 / CC6.2 | ⏳ **Pending** | v1.3 | **P3** |
| **Security & Defense** | Field-Level PII Envelope Encryption (AES-256-GCM / KMS) | NIST SP 800-38D | ✅ **Completed (ADR 0035)** | v1.3 | **P3** |
| **Security & Defense** | Distributed Credential Stuffing & ASN Velocity Defense | Threat Intelligence | ✅ **Completed (ADR 0037)** | v1.3 | **P3** |
| **Security & Defense** | Mutual TLS (mTLS) Zero-Trust Microservice Authentication | RFC 8705 / TLS 1.3 | ⏳ **Pending** | v1.3 | **P3** |
| **Security & Defense** | Honeytokens & Active Canary Secret Scanning | Deception Technology | ⏳ **Pending** | v1.3 | **P3** |
| **Audit & Compliance** | Immutable WORM Audit Archive (S3 Object Lock / Glacier) | SEC Rule 17a-4(f) | ⏳ **Pending** | v1.3 | **P3** |
| **Developer Experience** | Database Seed Script (`npm run db:seed`) | Developer Fixtures | ⏳ **Pending** | v1.1 | **P1** |

---

## 🎯 2. Active Roadmap Focus & Immediate Backlog

### 2.1 Next Recommended Feature: WebAuthn / FIDO2 Passkeys (ADR 0029)
- **Objective**: Phishing-resistant authentication (Touch ID, Face ID, YubiKey) bound to domain origin (`rpId`).
- **Standard**: W3C WebAuthn Level 3 / FIDO2.
- **Components**:
  - `POST /api/v1/auth/passkeys/register/start`: Challenge generation and attestation options.
  - `POST /api/v1/auth/passkeys/register/finish`: Cryptographic signature verification and credential persistence.
  - `POST /api/v1/auth/passkeys/authenticate/start`: Assertion challenge emission.
  - `POST /api/v1/auth/passkeys/authenticate/finish`: Public-key signature validation and counter clone detection.

### 2.2 Secondary Fast-Follows
1. **Password History Enforcement (NIST SP 800-63B)**:
   - Prevent recycling previous 10 Argon2id password hashes stored in `auth_password_history`.
2. **Machine-to-Machine (M2M) Client Credentials Grant (RFC 6749 §4.4)**:
   - Automated server-to-server token issuance for daemon microservices.

---

## 🔐 3. Deep-Dive: Security-Related Specifications

### 3.1 Dual-Track Rate Limiting & Bot Defense
- **Vulnerability Addressed**: Distributed brute-force, password guessing, and automated account lockout DoS.
- **Specification**:
  - Redis sliding-window counter tracking `login_failures:ip:{subnet}` and `login_failures:email:{email_hash}`.
  - IP threshold: 10 failures in 10 minutes $\rightarrow$ `HTTP 429 Too Many Requests` (`Retry-After: 600`).
  - Email threshold: 3 failures in 15 minutes $\rightarrow$ subsequent requests require valid `cf-turnstile-response` header + 2-second progressive delay.

### 3.2 Breached Password Detection (HaveIBeenPwned k-Anonymity)
- **Vulnerability Addressed**: Credential stuffing using compromised passwords from public breaches.
- **Specification**:
  - On user sign-up and password update, compute SHA-1 of candidate password.
  - Query HaveIBeenPwned API using **k-anonymity**: send only first 5 characters of SHA-1 hash (`GET https://api.pwnedpasswords.com/range/{prefix}`).
  - Match remainder locally. If the password appears in breach dumps, reject with `400 Bad Request`. Zero password material ever leaves the auth server.

### 3.3 Step-Up Authentication for High-Value Actions (RFC 9470)
- **Vulnerability Addressed**: Unauthorized execution of destructive actions via hijacked or abandoned sessions.
- **Protected Endpoints**:
  1. `POST /api/v1/auth/admin/impersonate/:user_id` (Account Takeover Guard)
  2. `DELETE /api/v1/auth/organizations/:id` (Organization Destruction)
  3. `POST /api/v1/auth/api-keys` with `tier: super_secret` (High-Privilege Credential Creation)
  4. `PATCH /api/v1/auth/users/:id/role` to `owner` or `admin` (Privilege Escalation)
  5. `POST /api/v1/auth/mfa/disable` (Security Control Downgrade)
- **Specification**:
  - Requires fresh re-authentication token (`reauth_token`) generated within last **300 seconds (5 minutes)**.
  - If missing or expired, return `HTTP 403 Forbidden` with header `WWW-Authenticate: StepUp max_age=300`.

### 3.4 Unified Adaptive Risk-Based Authentication (Soft Step-Up)
- **Vulnerability Addressed**: Static authentication barriers that fail against targeted attacks, while avoiding false-positive session disruption for mobile and VPN users.
- **Specification**:
  - Calculate dynamic Risk Score ($0 - 100$):
    - Known Datacenter/Proxy/Tor ASN: $+40$ risk.
    - Extreme Velocity ($>900\text{ km/h}$ between consecutive geographic locations): $+35$ risk.
    - Unrecognized Browser Fingerprint / User-Agent Shift: $+25$ risk.
  - **Action Thresholds**:
    - `Risk < 30`: Normal seamless access.
    - `30 <= Risk < 75`: Soft Step-Up Challenge (Prompts TOTP, WebAuthn passkey, or sends a 6-digit confirmation code).
    - `Risk >= 75`: Reject authentication with security notification dispatched to user and SIEM alert.

### 3.5 Field-Level PII Envelope Encryption (AES-256-GCM & KMS)
- **Vulnerability Addressed**: Cleartext data exposure during database backups or database dump leaks.
- **Storage Model**:
  - Reversible fields (`email`, `phone`, `mfa_secret`) encrypted using AES-256-GCM with Data Encryption Keys (DEKs) wrapped by KMS Key Encryption Key (KEK).
  - Irreversible fields (MFA recovery codes) stored as salted SHA-256 hashes (one-time burn on use).
  - Blind indexes (HMAC-SHA256 with tenant salt) used for exact-match database queries (`email_hash`).

### 3.6 Cryptographic Shredding & Right-To-Be-Forgotten (GDPR Art. 17)
- **Vulnerability Addressed**: Inability to purge PII from immutable database backups and write-ahead logs (WAL).
- **Specification**:
  - Every user identity has a dedicated AES-256 DEK stored in an isolated Key Vault table.
  - Upon user deletion or GDPR Article 17 execution, the user's DEK is securely zeroized from the Key Vault.
  - Historical snapshots and WAL records become mathematically unrecoverable noise immediately.

### 3.7 Standardized Asymmetric EdDSA (Ed25519) JWKS Key Rotation
- **Design Decision**: Standardize exclusively on **EdDSA (RFC 8037 curve Ed25519)** for asymmetric token signing.
- **Specification**:
  - Publish public keys via `GET /.well-known/jwks.json` using `kty: "OKP"` and `crv: "Ed25519"`.
  - Maintain active and retirement key IDs (`kid`) to support scheduled zero-downtime key rotation.

### 3.8 Automated Security Headers & Strict CSP (Nonces)
- **Vulnerability Addressed**: Cross-Site Scripting (XSS), Clickjacking, MIME-sniffing, and downgrade attacks.
- **Specification**:
  - `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` (HSTS).
  - `X-Content-Type-Options: nosniff`.
  - `X-Frame-Options: DENY`.
  - `Referrer-Policy: strict-origin-when-cross-origin`.
  - `Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()`.
  - Dynamic cryptographically secure base64 CSP nonce generated per request (`script-src 'nonce-{NONCE}' 'strict-dynamic'; object-src 'none'; base-uri 'none'`).

### 3.9 Anti-Homoglyph & Unicode Normalization Shield (NFKC / UTR 39)
- **Vulnerability Addressed**: Internationalized domain name (IDN) homograph attacks and Unicode visual spoofing.
- **Specification**:
  - Normalize all email and username inputs to Unicode Normalization Form KC (NFKC) before validation.
  - Reject registrations containing mixed-script confusable characters targeting registered tenant domains or administrative accounts.

### 3.10 Webhook Cryptographic Signatures & Anti-Replay Nonces
- **Vulnerability Addressed**: Man-in-the-middle tampering, spoofed webhook payloads, and replay attacks.
- **Specification**:
  - Outbound webhooks include headers `X-Auth-Signature: t={timestamp},v1={hmac_sha256_hex}` and `X-Auth-Nonce: {uuid_v4}`.
  - Signature calculated over `t.{timestamp}.payload.{body}` using tenant shared secret.
  - Tolerance window: receivers reject webhooks where `|current_time - timestamp| > 300` seconds.

---

## 🔑 4. Deep-Dive: Auth-Related Specifications

### 4.1 Multi-Factor Authentication (RFC 6238 TOTP & Salted Recovery Codes)
- **Endpoints**:
  - `POST /api/v1/auth/mfa/setup`: Generates secure base32 secret and `otpauth://` QR code URI.
  - `POST /api/v1/auth/mfa/verify`: Validates 6-digit TOTP code and activates MFA on account.
  - `POST /api/v1/auth/mfa/recovery-codes`: Generates 10 single-use random recovery codes.
- **Storage Model**:
  - Recovery codes hashed with salted SHA-256 prior to database insertion (`auth_recovery_codes`).
  - Row permanently deleted upon successful use (one-time burn).

### 4.2 Refresh Token Rotation & Family Reuse Detection
- **Endpoints**:
  - `POST /api/v1/auth/refresh`: Exchanges valid refresh token for fresh access token (15m TTL) and new refresh token (7d TTL).
- **Security Protections**:
  - Refresh tokens stored in `HttpOnly; Secure; SameSite=Lax` cookies.
  - If an already-used refresh token is presented, revoke the entire token family immediately.

### 4.3 Super-Admin User Impersonation
- **Mandatory Controls**:
  1. Fresh 5-minute `reauth_token` required.
  2. Strict 15-minute maximum session expiry (non-refreshable).
  3. Automated notification email instantly dispatched to target user.
  4. Tenant boundaries enforced (Organization Admins cannot impersonate across tenants).
  5. Audit attributes `{ impersonated_by: admin_user_id, ticket_id: "..." }` embedded in all logs.

### 4.4 Organization Domain Claiming & Email-Verified Auto-Join
- **Specification**:
  - Enterprises claim email domains via DNS TXT record verification.
  - New users registering with matching corporate domains are held in pending status until email ownership is cryptographically verified via confirmation token or corporate SSO/SAML assertion.

### 4.5 Multi-Device Session Management
- **Endpoints**:
  - `GET /api/v1/auth/sessions`: Lists active user sessions with IP, location, browser, OS, login timestamp, and `is_current` flag.
  - `DELETE /api/v1/auth/sessions/:session_id`: Revokes specific remote session.
  - `DELETE /api/v1/auth/sessions`: Revokes all other active sessions.

### 4.6 SCIM 2.0 Directory Provisioning (RFC 7643 & RFC 7644)
- **Endpoints**:
  - `GET/POST /scim/v2/Users`: Enumerates and provisions enterprise directory users.
  - `GET/PATCH/DELETE /scim/v2/Users/:id`: Inspects, modifies, and deprovisions user access.
  - `GET/POST/PATCH/DELETE /scim/v2/Groups`: Manages directory team groups.

### 4.7 Enterprise SAML 2.0 Service Provider Federation
- **Endpoints**:
  - `GET /api/v1/auth/saml/metadata`: Publishes SP metadata XML with X.509 signing certificates.
  - `GET /api/v1/auth/saml/login`: Initiates SP-initiated SSO returning AuthNRequest and signed RelayState.
  - `POST /api/v1/auth/saml/acs`: Assertion Consumer Service verifying XMLDSig signatures, clock skew, and replay rejection.

### 4.8 Zero-Trust API Key Network Ingress & Rate Quotas (ADR 0027)
- **Endpoints**:
  - `POST /api/v1/auth/api-keys`: Creates key with `ip_allowlist` CIDRs and `rate_quota_rpm`.
  - `POST /api/v1/auth/api-keys/verify`: Evaluates client IP against CIDR subnets and checks atomic sliding 60s epoch rate quota.
  - `GET/PATCH /api/v1/auth/api-keys/:id/allowlist`: Manages key allowlists dynamically.
  - Automatic anomaly detection: flags `anomaly_flag = TRUE` when traffic breaches $3\times$ quota.

---

## 🛠 5. Compliance & Operational Backlog

- [x] **Automated 30-Day Cascade Soft-Delete Purge Cron Worker (ADR 0016)**:
  - Nightly worker hard-purging records where `deleted_at_ms < (now - 30 days)`.
- [x] **GDPR DSAR JSON Export Endpoint (ADR 0017)**:
  - Endpoint `GET /api/v1/auth/users/me/export` returning machine-readable JSON archive.
- [ ] **Automated Database Seeder (`database/seeds/seed.ts`)**:
  - `npm run db:seed`: Populates development fixtures (Default Organization, Admin, Viewer, pre-seeded API keys).
- [ ] **Prometheus Alert Rules for Authentication**:
  - High Failure Rate: Alert if sign-in failure rate exceeds 5% over 5 minutes.
  - Brute Force Spikes: Alert if lockout events exceed 10 per minute.
  - High Latency: Alert if p95 authentication latency exceeds 300ms.

# 📐 Auth Service Architecture Decision Records (ADRs) & Troubleshooting Guides

This directory contains formal Architecture Decision Records (ADRs) and operational troubleshooting guides for `@observability/auth`, detailing High-Level Designs (HLD), Low-Level Designs (LLD), sequence diagrams, component topologies, TraceQL queries, and architectural trade-offs.

---

## 📚 ADR Index & Guides

| Document | Title | Scope / Topics | Status |
|---|---|---|---|
| [**0001**](./0001-hexagonal-architecture-and-rule-engine-router.md) | Hexagonal Architecture & Declarative Rule Engine Router | Ports & Adapters separation, Rule Engine route matching, OpenTelemetry span wrapping | Accepted |
| [**0002**](./0002-authentication-user-registration-and-signin-flow.md) | Sign-Up, Sign-In, Argon2id Hashing & Audit Logging | Dual-phase authentication flow, Argon2id hash validation, Audit trail capture, Full Call Stack | Accepted |
| [**0003**](./0003-multi-tenant-organization-switching-and-rls.md) | N-to-N Multi-Tenancy & Org Context Switching | Row-Level Security (RLS), multi-tenant org switching, JWT claim re-issuance | Accepted |
| [**0004**](./0004-session-revocation-redis-token-denylist.md) | Redis Token Denylist & Session Lifetime Management | Server-side JWT session invalidation, Redis O(1) denylist lookup, 401 auto-logout | Accepted |
| [**0005**](./0005-opentelemetry-end-to-end-auth-tracing-and-middleware.md) | OpenTelemetry End-to-End Authentication Tracing & Middleware | NodeTracerProvider OTLP exporter, traceHttpMiddleware, W3C trace propagation, Tempo integration | Accepted |
| [**0006**](./0006-kafka-messaging-pipeline-and-distributed-tracing.md) | Kafka Messaging Pipeline & Distributed Tracing Architecture | Centralized Kafka client, Producer/Consumer middleware pipelines, W3C message header propagation | Accepted |
| [**0007**](./0007-alloydb-omni-resource-constraints-and-oltp-tuning.md) | AlloyDB Omni Resource Constraints, Memory Optimization & OLTP Tuning | Memory limits, disabling columnar engine, shared_buffers sizing, and preventing g_term_it OOM kills | Accepted |
| [**0008**](./0008-master-api-catalog-parameter-contracts-and-response-envelopes.md) | Master API Catalog, Parameter Contracts & Response Envelopes | Complete reference for all 34 endpoints, schemas, parameters, success/error envelopes, and live curl verification | Accepted |
| [**0009**](./0009-docker-production-image-optimization-tree-shaking-and-v8-memory-tuning.md) | Docker Production Image Optimization, Tree-Shaking & V8 Memory Tuning | Multi-stage build, esbuild tree-shaking, node:26-alpine preservation, -99% app layer, 32MB RAM, and Docker Hub deployment | Accepted |
| [**0010**](./0010-redis-jti-session-denylist-and-adaptive-login-rate-limiting.md) | Redis JTI Session Denylist & Adaptive Login Rate Limiting | Stateless JTI token revocation, O(1) Redis cache, sliding window IP rate limiting, account lockout | Accepted |
| [**0011**](./0011-api-key-engine-ttl-revocation-and-transactional-mailer.md) | API Key Engine (TTL & Instant Revocation) & Transactional Mailer Subsystem | Ephemeral super_secret key TTL enforcement, Redis edge revocation denylist, MailerPort adapter-port pattern, ScalableHttpClient resilience, email verification | Accepted |
| [**0012**](./0012-multi-factor-authentication-rfc6238-totp-and-recovery-codes.md) | Multi-Factor Authentication Architecture (RFC 6238 TOTP & Salted Recovery Codes) | RFC 6238 TOTP engine, Base32 secrets, Two-stage login challenge, SHA-256 hashed single-use recovery codes, Anti-replay defense | Accepted |
| [**0013**](./0013-step-up-authentication-rfc9470-and-high-value-action-protection.md) | Step-Up Authentication for High-Value Actions (RFC 9470) | Ephemeral HMAC-SHA256 re-auth tokens, 300s TTL, WWW-Authenticate StepUp challenge, declarative router guard, high-value action protection | Accepted |
| [**0014**](./0014-refresh-token-rotation-and-family-reuse-detection.md) | Refresh Token Rotation & Family Reuse Detection (RFC 6749 §10.4) | Single-use refresh token exchange, automatic family invalidation on token reuse, sliding-window session renewal | Accepted |
| [**0015**](./0015-breached-password-screening-nist-sp800-63b-k-anonymity.md) | Breached Password Screening (NIST SP 800-63B / k-Anonymity) | HaveIBeenPwned k-anonymity range API, 5-char SHA-1 prefix screening, zero plain-text password leakage, fail-open resilience | Accepted |
| [**0016**](./0016-automated-30-day-cascade-soft-delete-purge-worker-gdpr-art17.md) | Automated 30-Day Cascade Soft-Delete Purge Cron Worker (GDPR Art. 17) | Autonomous scheduled purge worker, distributed mutex locking, cascade deletion, GDPR right-to-be-forgotten compliance | Accepted |
| [**0017**](./0017-gdpr-article-15-dsar-json-export.md) | GDPR Article 15 Data Subject Access Request (DSAR) JSON Export | Machine-readable data subject archive, zero credential leakage sanitization, multi-relation aggregation | Accepted |
| [**0018**](./0018-automated-security-headers-and-strict-csp.md) | Automated Security Headers & Strict Content Security Policy (CSP Nonces) | W3C CSP Level 3, RFC 6797 HSTS, dynamic cryptographic nonces, zero code-change declarative config | Accepted |
| [**0019**](./0019-multi-device-session-management-and-remote-kill.md) | Multi-Device Session Management & Remote Kill (OWASP ASVS 3.3) | Active session listing, device telemetry, single remote session termination, and bulk sign-out-all-other-devices | Accepted |
| [**0020**](./0020-federated-identity-provider-oauth2-oidc-sso-and-account-linking.md) | Federated Identity Provider (OAuth 2.0 / OIDC) SSO & Account Linking | Google / GitHub OAuth2 & OIDC federation, CSRF state verification, account linking, federated identities | Accepted |
| [**0021**](./0021-organization-domain-claiming-and-verified-auto-join.md) | Organization Domain Claiming & Verified Auto-Join (DNS TXT + Email Gate) | DNS TXT verification challenges, background re-check worker, corporate domain claiming, automated onboarding tenant routing | Accepted |
| [**0022**](./0022-unified-adaptive-risk-based-authentication.md) | Unified Adaptive Risk-Based Authentication (Soft Step-Up) | NIST SP 800-63-3 dynamic risk scoring (0-100), Haversine impossible velocity (>900 km/h), ASN proxy detection, ephemeral challenge resolution | Accepted |
| [**0023**](./0023-fine-grained-policy-engine-abac-rebac.md) | Fine-Grained Policy Engine (ABAC / ReBAC) with Zanzibar-Style Relationship Tuples | Zanzibar-style 6-ary tuples, dynamic ABAC conditions, transitive role inheritance, sub-millisecond evaluation | Accepted |
| [**0024**](./0024-scim-2-user-and-group-provisioning-api.md) | SCIM 2.0 User & Group Provisioning API (RFC 7643 / RFC 7644) | Automated Okta / Entra ID identity lifecycle, push provisioning, group sync, instant deprovisioning & remote session kill | Accepted |
| [**Troubleshooting Guide**](../docs/troubleshooting-and-grafana-guide.md) | Troubleshooting & Grafana Tempo Debugging Guide | TraceQL queries, Grafana setup, time-range filtering, error debugging & fixes | Active Guide |
| [**Staff & Principal Q&A Catalog**](./q&a/README.md) | Comprehensive 275+ Question Architectural Interview Catalog | 25+ in-depth technical questions & meta-questions per ADR covering all failure modes, trade-offs, and invariants | Active Catalog |




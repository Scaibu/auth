# 📋 Security, Hardening & Engineering Roadmap (TODO.md)

*Prioritized, actionable checklist for tenant isolation, token lifecycle, infrastructure hardening, and quantum/AI-resilient identity.*

---

## 🚦 Summary Status Dashboard

- **P0 / Tier 0 (Immediate Security & Blast Radius)**: 5/10 completed
- **P1 / Tier 1 (100+ App Reliability & Scaling)**: 0/12 completed
- **P2 / Tier 2 (Compliance, Supply Chain & Governance)**: 0/8 completed
- **Post-Quantum Cryptography Readiness**: 0/11 completed
- **AI Agent Identity & Authorization**: 0/10 completed
- **Assurance & Verification**: 0/5 completed

---

## 🔴 Priority 0 / Tier 0: Critical Isolation & Blast Radius (Fix First)

- [x] **1. Prove RLS Actually Enforces Isolation (Non-Superuser App Role)**
  - **Context**: Documented run connects as `postgres`. Superusers and `BYPASSRLS` roles skip RLS entirely (`FORCE ROW LEVEL SECURITY` does not override this).
  - [x] Configure database role: Run application as non-owner, non-superuser role (e.g. `auth_app`).
  - [x] Enforce per-transaction tenant isolation using `SET LOCAL app.current_tenant_id = ...` inside transactions.
  - [x] Prevent tenant leakage across pooled connections (PgBouncer transaction-pooling compliance).
  - [x] Add CI check to assert app DB role lacks `SUPERUSER` and `BYPASSRLS`.
  - [x] **Acceptance Test**: Automated test authenticated as Tenant A queries all tables and reads 0 rows belonging to Tenant B.

- [x] **2. Bounded Token Revocation & Active Lifecycle Sync**
  - **Context**: JWTs are verified locally via JWKS; Keycloak-side disablement (`setUserEnabled(false)`) is invisible until token TTL expires. API keys bypass Keycloak entirely.
  - [x] Re-check DB active status of user/organization on every API key and break-glass invocation.
  - [x] Implement Keycloak event consumer (`USER_DELETE`, `USER_UPDATE`, logout) or OpenID Shared Signals (CAEP).
  - [x] Add periodic full user status reconciliation between Keycloak and local DB.
  - [x] Enforce token introspection for high-risk / sensitive operations.
  - [x] **Acceptance Test**: Disabling or deleting a user invalidates their JWT and API keys across all endpoints within 30 seconds.

- [x] **3. Per-App Token Audience & Scope Binding**
  - **Context**: A single shared token valid across 100+ apps allows lateral privilege escalation if any downstream app is compromised.
  - [x] Require explicit `aud` (audience) claim validation per service/application.
  - [x] Implement RFC 8693 OAuth Token Exchange or client-scoped token issuance for service boundaries.
  - [x] Document versioned token claim schema (`sub`, `tenant_id`, `roles`, `aud`).
  - [x] **Acceptance Test**: A token issued for App X is strictly rejected (401/403) when presented to App Y.

- [x] **4. Clear Source of Truth for Tenant & Role Authorization**
  - **Context**: Tenant/role claims exist in JWTs and the application DB; token claims go stale on permission changes.
  - [x] Formalize model: Token proves identity (`sub`) only; authorization/roles/org membership resolved from application DB / policy store.
  - [x] Update ADRs and documentation to define authority hierarchy.
  - [x] **Acceptance Test**: Demoting a user in the application DB immediately drops their privileges on the next request without waiting for token expiry.

- [x] **5. Keycloak Realm Hardening as Code**
  - **Context**: Default Keycloak setup allows brute-force attacks and wildcard redirect URIs (`localhost:3000/*`).
  - [x] Enable Keycloak brute-force protection and lockout policies.
  - [x] Enforce PKCE (`S256`) on all OIDC clients.
  - [x] Restrict redirect URIs to strict exact-match in staging and production.
  - [x] Disable unused flows (Implicit flow, Direct Grant / ROPC).
  - [x] Enable refresh token reuse detection and revoking on exchange.
  - [x] Isolate Keycloak Admin Console to private/internal network.
  - [x] Export realm configuration to versioned JSON/Terraform with automated drift detection.
  - [x] **Acceptance Test**: CI fails if exported realm configuration drifts from hardened baseline.

- [ ] **6. Secrets Management & Public Repo Sanitization**
  - **Context**: Default configurations and README contain static credentials and obsolete `JWT_SECRET`.
  - [ ] Rotate all previously exposed credentials (database, Redis, Keycloak admin passwords).
  - [ ] Remove hardcoded credentials from `README.md`, environment files, and documentation.
  - [ ] Migrate secret storage to KMS / Vault / Cloud Secrets Manager.
  - [ ] Add automated pre-commit and CI secret scanning (e.g. Gitleaks / GitHub Secret Protection).
  - [ ] Document emergency secret rotation runbook.
  - [ ] **Acceptance Test**: Zero plaintext secrets in repository or git commit history; rotation runbook rehearsed.

- [ ] **7. API Key Subsystem Hardening**
  - **Context**: Longest-lived bearer credentials in the system; primary M2M authentication path.
  - [ ] Store only salted hashes (HMAC-SHA256 with KMS pepper or high-workfactor hash).
  - [ ] Use high-entropy lookup prefixes (e.g., `llmobs_live_...`) with constant-time comparison (`crypto.timingSafeEqual`).
  - [ ] Register secret scanning signature with GitHub / secret scanners.
  - [ ] Implement key expiration, scoped permissions, and overlapping rotation support.
  - [ ] Track `last_used_at` timestamp and calling IP / CIDR.
  - [ ] **Acceptance Test**: A database dump yields 0 usable API keys; a leaked key is identified and revocable within minutes.

- [ ] **8. Comprehensive Cross-Tenant & Negative Security Test Suite**
  - **Context**: Core attack surface (API keys, ReBAC, quotas, honeytokens) needs automated negative testing.
  - [ ] Add negative tests for IDOR across all tenant-scoped routes.
  - [ ] Add privilege escalation test cases (e.g. non-admin attempting policy edits).
  - [ ] Add negative tests for cross-tenant reads and writes.
  - [ ] Add tests for expired, manipulated, and revoked credentials.
  - [ ] Integrate mutation testing on authorization middleware.
  - [ ] **Acceptance Test**: Every authenticated route has at least one test asserting 403 or 404 for foreign tenant credentials.

- [ ] **9. ReBAC Policy Engine Correctness & DoS Resistance**
  - **Context**: Graph-based policy engines can suffer from cycles, unbounded depth, and high evaluation latency.
  - [ ] Enforce strict depth and fan-out recursion limits in Zanzibar graph evaluation.
  - [ ] Implement cycle detection during graph traversal.
  - [ ] Add check latency timeouts that fail closed (deny access).
  - [ ] Define and document consistency guarantees (Zanzibar zookies or read-after-write consistency).
  - [ ] **Acceptance Test**: Adversarial recursive policy graphs cannot push p99 check latency above defined SLO threshold (e.g. 50ms).

- [ ] **10. CIDR Allowlist & Trusted Proxy Verification**
  - **Context**: IP-based access control and CIDR matching can be spoofed if `X-Forwarded-For` is trusted unconditionally.
  - [ ] Audit Traefik / reverse-proxy header forwarding.
  - [ ] Pin trusted proxy CIDRs in Express / Fastify / Node HTTP stack.
  - [ ] Verify that client-supplied `X-Forwarded-For` headers from untrusted hops are stripped/ignored.
  - [ ] **Acceptance Test**: Automated test through proxy verifies that spoofed client IP headers fail CIDR authorization.

---

## 🟡 Priority 1 / Tier 1: Reliability & Operations at 100+ App Scale

- [ ] **11. Keycloak High Availability & Clustering**
  - [ ] Run Keycloak in production mode (`start` instead of `start-dev`) with dedicated PostgreSQL database/schema.
  - [ ] Configure Infinispan distributed cache clustering across Keycloak instances.
  - [ ] Define capacity model based on aggregate login and token refresh rates across all 100+ services.
  - [ ] Set up automated database and configuration backups.
  - [ ] **Acceptance Test**: Killing a Keycloak node during simulated load test results in zero login failures.

- [ ] **12. Graceful Degradation on Keycloak / JWKS Outages**
  - [ ] Implement bounded stale JWKS caching (continue serving cached keys if Keycloak is temporarily down).
  - [ ] Fail closed on unknown key IDs (`kid`).
  - [ ] Implement circuit breaker around Keycloak Admin API calls.
  - [ ] Support seamless overlapping key rotations.
  - [ ] **Acceptance Test**: Chaos tests verify the service rejects untrusted tokens and degrades gracefully during Keycloak downtime.

- [ ] **13. Declarative Realm-as-Code & Startup Seed Automation**
  - [ ] Implement idempotent realm seed script (`scripts/seed-keycloak-realm.ts`) or Terraform provider.
  - [ ] Programmatically bootstrap realm, clients, scopes, mappers, and identity providers.
  - [ ] **Acceptance Test**: Blank Keycloak instance is completely configured and ready for production in a single pipeline run.

- [ ] **14. Automated Client Onboarding & Offboarding Lifecycle**
  - [ ] Create self-service client application registration workflow with validation.
  - [ ] Automatically generate strong client credentials and register least-privilege scopes.
  - [ ] Automated client de-provisioning and credential revocation.
  - [ ] **Acceptance Test**: New client application onboarded and verified in < 15 minutes with zero manual Keycloak GUI edits.

- [ ] **15. Standardized Gateway Verification & Shared Verification Library**
  - [ ] Enforce edge token verification using Traefik `forwardAuth`.
  - [ ] Provide unified, tested TypeScript / Go middleware library with automated CVE patching.
  - [ ] Disallow ad-hoc JWT validation logic across individual consumer microservices.
  - [ ] **Acceptance Test**: All downstream services rely strictly on edge gateway or unified library for session validation.

- [ ] **16. Per-Tenant and Per-App Rate Limiting & Quotas**
  - [ ] Implement rate limiting partitioned by `tenant_id` and `client_id`.
  - [ ] Add load-shedding and bulkheads around compute-heavy ReBAC graph checks.
  - [ ] **Acceptance Test**: A rogue or noisy tenant exceeding limits is throttled without degrading p99 latency for other tenants.

- [ ] **17. Connection Pool & RLS Isolation Verification**
  - [ ] Ensure all tenant-scoped database queries execute inside transactions using `SET LOCAL`.
  - [ ] Size PgBouncer / database connection pools for high-concurrency 100+ app scale.
  - [ ] Implement alerts on connection pool exhaustion.
  - [ ] **Acceptance Test**: Concurrent queries from interleaved tenants never see cross-tenant rows.

- [ ] **18. Performance SLOs & Authorization Latency Baselines**
  - [ ] Define formal SLOs (e.g. Auth check p99 < 30ms, availability > 99.99%).
  - [ ] Instrument Prometheus metrics for auth latency, cache hits/misses, and decision throughput.
  - [ ] Conduct load testing at 3x expected peak load.
  - [ ] **Acceptance Test**: Load testing proves compliance with p99 latency SLOs under peak load.

- [ ] **19. Zero-Downtime Database Migration Discipline**
  - [ ] Mandate expand/contract pattern for all future schema migrations.
  - [ ] Add lock-timeout guards and non-blocking index creation (`CONCURRENTLY`).
  - [ ] Index foreign keys and `tenant_id` on all tenant-isolated tables.
  - [ ] **Acceptance Test**: Schema migrations execute with verified zero downtime and documented rollback steps.

- [ ] **20. Unified Tamper-Evident Audit Pipeline**
  - [ ] Ingest Keycloak authentication events (logins, MFA, failures) into `auth_audit_logs`.
  - [ ] Publish audit records to append-only Kafka topic (`auth.events.v1`).
  - [ ] Implement idempotent consumers with Dead Letter Queues (DLQ).
  - [ ] Implement cryptographic tamper evidence (SHA-256 hash chaining or Merkle tree).
  - [ ] Time-partition database audit tables with retention policies.
  - [ ] **Acceptance Test**: Unified query can reconstruct a tamper-evident timeline of all actions by any user/tenant across 90 days.

- [ ] **21. Disaster Recovery & Backup Drills**
  - [ ] Define Recovery Point Objective (RPO) and Recovery Time Objective (RTO).
  - [ ] Establish atomic backup procedures covering Keycloak DB, App DB, and realm configs.
  - [ ] **Acceptance Test**: Semi-annual disaster recovery drill recovers the full auth cluster from cold backup within documented RTO.

- [ ] **22. Proactive Security Alerting & Observability**
  - [ ] Set up alerts on failed login anomalies and brute-force spikes.
  - [ ] Alert on JWKS fetch failures and token validation error spikes.
  - [ ] Alert on sudden increases in 401/403 responses per client application.
  - [ ] Provide Grafana dashboards visualizing Traefik $\to$ Auth Service $\to$ Keycloak $\to$ PostgreSQL trace paths.
  - [ ] **Acceptance Test**: Simulated brute-force or credential stuffing triggers alerts within 60 seconds.

---

## 🟢 Priority 2 / Tier 2: Governance, Compliance & Supply Chain

- [ ] **23. Data Retention & Right to Erasure (GDPR / Privacy)**
  - [ ] Harmonize Keycloak deletion and local DB soft-deletion (30-day retention).
  - [ ] Establish documented data erasure pipeline for PII across tables, audit logs, and backups.
  - [ ] Pseudonymize user identifiers in long-term audit logs.
  - [ ] **Acceptance Test**: User erasure request successfully purges PII across all data stores.

- [ ] **24. Tenant Offboarding & Data Portability**
  - [ ] Implement cascade archiving/deletion for organizations (API keys, ReBAC policies, memberships).
  - [ ] Provide tenant data export mechanism.
  - [ ] **Acceptance Test**: Offboarding a test organization leaves zero orphan rows in the database.

- [ ] **25. Documentation Accuracy & ADR Maintenance**
  - [ ] Update README to reflect current Keycloak OIDC architecture and remove legacy references.
  - [ ] Mark obsolete ADRs (ADR 0002 - ADR 0004) as `SUPERSEDED`.
  - [ ] Clarify Redis operational responsibilities in current architecture.
  - [ ] Write operational runbooks (Keycloak outage, compromised secret, tenant isolation breach).
  - [ ] **Acceptance Test**: A new engineer can deploy, configure, and troubleshoot the auth service using docs alone.

- [ ] **26. Emergency Break-Glass Governance**
  - [ ] Require dual-authorization (two-person rule) for emergency break-glass activation.
  - [ ] Enforce short hard session expiration (maximum 1-4 hours).
  - [ ] Dispatch high-priority alert to security team upon break-glass session initiation.
  - [ ] Mandate post-incident review record linked to break-glass session ID.
  - [ ] **Acceptance Test**: Every break-glass activation sends immediate alert and records an unalterable audit log.

- [ ] **27. Software Supply Chain & Build Integrity**
  - [ ] Pin all base Docker images by cryptographic digest (`sha256:...`).
  - [ ] Generate Software Bill of Materials (SBOM) in CI (CycloneDX / SPDX).
  - [ ] Integrate dependency vulnerability scanning with build-blocking thresholds.
  - [ ] Sign container images using Sigstore (Cosign).
  - [ ] Internalize and version `@chief-strategist-j/shared-infra` dependency under organizational ownership.
  - [ ] **Acceptance Test**: CI pipeline blocks builds on unsigned images or critical unresolved vulnerabilities.

- [ ] **28. API Contract Governance & Breaking Change Prevention**
  - [ ] Automate OpenAPI linting and contract validation against `contracts/openapi/v1.yaml`.
  - [ ] Add breaking-change detection in CI (e.g. `oasdiff`).
  - [ ] Establish documented versioning and deprecation policy with required notice window.
  - [ ] **Acceptance Test**: CI fails if a pull request introduces an unversioned breaking change to public API contracts.

- [ ] **29. Service-to-Service Workload Identity**
  - [ ] Transition internal microservice M2M communications from static API keys to OAuth2 Client Credentials / mTLS.
  - [ ] Reserve API keys for external developer access and CLI tooling.
  - [ ] **Acceptance Test**: Internal service calls operate without long-lived bearer credentials.

- [ ] **30. Phishing-Resistant Authentication Policy**
  - [ ] Enforce FIDO2 / WebAuthn passkeys or hardware security keys for administrator accounts.
  - [ ] Remove SMS and email OTP fallbacks for privileged roles.
  - [ ] Harden account recovery flows against social engineering.
  - [ ] **Acceptance Test**: Privileged administrator accounts cannot authenticate with phishable factors.

---

## 🔬 Tier B: Cryptography & Quantum Readiness

- [ ] **31. Cryptographic Bill of Materials (CBOM)**
  - [ ] Catalog all cryptographic algorithms, key lengths, certificates, and libraries in use.
  - [ ] Map data-secrecy horizons against post-quantum risk timelines.
  - [ ] Automate CBOM generation in CI.
  - [ ] **Acceptance Test**: Verified CBOM artifact generated on every release.

- [ ] **32. Cryptographic Agility & Algorithm Versioning**
  - [ ] Decouple cryptographic algorithms from application code into configuration.
  - [ ] Support multi-algorithm verification in JWKS keyed by `kid`.
  - [ ] Version stored ciphertext envelopes and hashes (`v1`, `v2`, etc.).
  - [ ] **Acceptance Test**: Signing algorithm can be rotated in staging without verifier code changes.

- [ ] **33. Hybrid Post-Quantum Key Exchange in Transit**
  - [ ] Enable hybrid X25519 + ML-KEM-768 (FIPS 203) on ingress and inter-service TLS where supported.
  - [ ] Audit TLS configurations across Traefik, Node.js, and database connections.
  - [ ] **Acceptance Test**: Network capture confirms hybrid key exchange negotiation on ingress connections.

- [ ] **34. Per-Tenant Envelope Encryption with Quantum Safety**
  - [ ] Implement AES-256-GCM tenant data encryption keys (DEK) wrapped by KMS Key Encryption Keys (KEK).
  - [ ] Enable crypto-shredding (instant tenant data obliteration by deleting tenant KEK).
  - [ ] Plan wrapping layer transition to ML-KEM when cloud KMS supports post-quantum algorithms.
  - [ ] **Acceptance Test**: Deleting a tenant's key renders their database and backup data irrecoverable.

- [ ] **35. Post-Quantum Long-Term Audit & Signature Tracking**
  - [ ] Enforce SHA-384 or SHA-512 hash chains for long-term audit trail durability.
  - [ ] Track IETF standardization of ML-DSA (FIPS 204) for JOSE / JWT tokens.
  - [ ] Maintain vendor post-quantum questionnaires for Keycloak, Postgres, Kafka, and Redis.
  - [ ] **Acceptance Test**: Verification tool confirms audit trail integrity against simulated historical tampering.

---

## 🤖 Tier C: AI-Era Threats & Agent Identity

- [ ] **36. Three-Tier Agent Identity Model (Class, Instance, Session)**
  - [ ] Define explicit data models for AI Agents:
    - **Class**: Manifest, model configuration, and code hash.
    - **Instance**: Ephemeral runtime process execution.
    - **Session**: Specific task execution context.
  - [ ] Enforce invariant: An instance or session cannot outlive its parent class revocation.
  - [ ] Bind every agent session to an accountable human principal.
  - [ ] **Acceptance Test**: Deactivating an agent class or human principal immediately revokes all descendant running instances.

- [ ] **37. Monotonic Attenuation & Delegation Chains**
  - [ ] Implement capability-based tokens for agent delegation where permissions can only narrow, never expand:
    $$\text{authority}(\text{child}) \subseteq \text{authority}(\text{parent})$$
  - [ ] Implement delegation depth limits, fan-out limits, and loop detection.
  - [ ] Track delegation chains using RFC 8693 `act` (actor) claims.
  - [ ] **Acceptance Test**: Property tests verify child agents cannot gain privileges outside parent bounds.

- [ ] **38. Deterministic Policy Enforcement (Model Output Is Untrusted)**
  - [ ] Enforce all authorization decisions in deterministic policy layer (ReBAC / PDP); never allow LLM outputs to decide permissions.
  - [ ] Pass tools and capabilities by reference rather than raw prompt text.
  - [ ] Implement spend, rate, and time budgets enforced externally on agent execution.
  - [ ] **Acceptance Test**: Red-team tests with prompt injection attempts fail to execute out-of-scope tools.

- [ ] **39. Agent Speed Revocation & Shared Signals**
  - [ ] Implement sub-second agent session revocation using ephemeral token TTLs and epoch-based subtree invalidation.
  - [ ] Propagate revocation via CAEP / Shared Signals across agent workers.
  - [ ] **Acceptance Test**: Revoking an agent session terminates sub-agent execution within < 5 seconds.

- [ ] **40. Action-Bound Receipts & SCITT Audit Logging**
  - [ ] Generate signed receipts for high-impact agent actions linked to the delegation chain.
  - [ ] Log action receipts to append-only transparency ledger.
  - [ ] Support redaction of sensitive prompts/PII without breaking hash verification.
  - [ ] **Acceptance Test**: Auditor can trace any agent API action back to the authorising human principal and intermediate delegates.

---

## 🛡️ Tier D: Formal Assurance & Verification

- [ ] **41. Formal Specification of Isolation & Revocation**
  - [ ] Model multi-tenant RLS isolation and revocation invariants in TLA+ or Alloy.
  - [ ] Formally verify that under all concurrent execution schedules, no tenant can read foreign records.
  - [ ] **Acceptance Test**: Model checker completes state exploration with 0 invariant violations.

- [ ] **42. Threat Modeling & Attack Trees**
  - [ ] Conduct STRIDE and attack tree analysis for trust boundaries:
    - Compromised Keycloak instance
    - Rogue database administrator
    - Compromised downstream application among the 100+
    - Stolen backup artifact
  - [ ] **Acceptance Test**: Every identified threat links directly to an automated test, architectural control, or accepted risk entry.

- [ ] **43. Hardware-Rooted Signing & Key Isolation**
  - [ ] Isolate signing keys to non-exportable KMS / HSM hardware.
  - [ ] Mandate M-of-N quorum ceremonies for root key generation and rollover.
  - [ ] **Acceptance Test**: Application memory dumps contain zero private asymmetric signing keys.

- [ ] **44. Regular Red Team Drills & Mass Re-Key Exercises**
  - [ ] Conduct semi-annual drills testing complete credential and key rotation across all 100+ services.
  - [ ] Implement and publish `security.txt` and vulnerability disclosure program.
  - [ ] **Acceptance Test**: Timed drill rotates all signing keys and service credentials across the fleet within target window.

- [ ] **45. Continuous Adversarial Fuzzing**
  - [ ] Implement coverage-guided fuzzing for JWT, JWKS, HTTP header, and policy parsers.
  - [ ] Run fuzzing continuously in staging / nightly pipelines.
  - [ ] Maintain regression corpora for all past vulnerabilities.
  - [ ] **Acceptance Test**: Fuzzers run 10M+ iterations without unhandled panics or assertion failures.

---

## 📌 Implementation Hygiene Tasks (Deprioritized)

- [ ] **46. Shared-Infra HTTP Client Serialization Patch**
  - [ ] Patch `StepNetworkExecution` in `@chief-strategist-j/shared-infra` to avoid auto-`JSON.stringify` on form-urlencoded payloads.
  - [ ] Migrate `KeycloakApiAdapter` from `fetch` to shared `httpClient`.
- [ ] **47. Grafana Dashboard Visualizations**
  - [ ] Build visual telemetry dashboards for Traefik and Keycloak trace flows.
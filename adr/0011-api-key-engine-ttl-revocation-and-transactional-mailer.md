# ADR 0011: API Key Engine (TTL & Instant Revocation) and Transactional Mailer Adapter Architecture

- **Status**: Accepted
- **Date**: 2026-09-19
- **Deciders**: Observability Architecture Working Group, Platform Security Core
- **Context**: Enterprise observability backbones require strictly bounded ephemeral credentials for administrative operations (`ak_sec_` keys) with mandatory TTL enforcement and immediate edge revocation across multi-region edge nodes. Concurrently, multi-tenant authentication workflows (sign-up verification, team invitations, and password resets) require provider-agnostic, RFC 2045-compliant transactional email delivery with zero vendor lock-in, dynamic endpoint configuration, and fail-fast validation.

---

## 📑 Table of Contents

1. [High-Level Design (HLD)](#1-high-level-design-hld)
2. [Ports and Adapters (Hexagonal Architecture)](#2-ports-and-adapters-hexagonal-architecture)
3. [Low-Level Design (LLD) & Sequence Flows](#3-low-level-design-lld--sequence-flows)
   - [3.1 API Key Engine: TTL Enforcement, Instant Revocation & Telemetry](#31-api-key-engine-ttl-enforcement-instant-revocation--telemetry)
   - [3.2 Transactional Mailer: Fail-Fast Execution Pipeline](#32-transactional-mailer-fail-fast-execution-pipeline)
   - [3.3 Email Verification: Sign-Up to Atomic Confirmation](#33-email-verification-sign-up-to-atomic-confirmation)
   - [3.4 SMTP Wire Protocol Exchange (RFC 5321 & RFC 3207)](#34-smtp-wire-protocol-exchange-rfc-5321--rfc-3207)
4. [Finite State Machines & Lifecycle Transitions](#4-finite-state-machines--lifecycle-transitions)
   - [4.1 API Key Lifecycle State Machine](#41-api-key-lifecycle-state-machine)
   - [4.2 Email Verification Token Lifecycle State Machine](#42-email-verification-token-lifecycle-state-machine)
5. [Open Standards & Protocol Specifications](#5-open-standards--protocol-specifications)
   - [5.1 MIME RFC 2045 & RFC 5322 Multipart Architecture](#51-mime-rfc-2045--rfc-5322-multipart-architecture)
   - [5.2 AWS Signature Version 4 (SigV4) Cryptographic Pipeline](#52-aws-signature-version-4-sigv4-cryptographic-pipeline)
   - [5.3 ScalableHttpClient 8-Step Resilience Pipeline](#53-scalablehttpclient-8-step-resilience-pipeline)
6. [Relational Database Schema & Migrations](#6-relational-database-schema--migrations)
7. [Distributed Observability & TraceQL Queries](#7-distributed-observability--traceql-queries)
8. [Comprehensive API Curl Reference & Protocol Payloads](#8-comprehensive-api-curl-reference--protocol-payloads)
   - [8.1 Create Ephemeral super_secret API Key (Mandatory TTL)](#81-create-ephemeral-super_secret-api-key-mandatory-ttl)
   - [8.2 Reject super_secret Key Missing TTL](#82-reject-super_secret-key-missing-ttl)
   - [8.3 Reject super_secret Key Exceeding 90-Day Max TTL](#83-reject-super_secret-key-exceeding-90-day-max-ttl)
   - [8.4 Verify API Key & Record Usage Telemetry](#84-verify-api-key--record-usage-telemetry)
   - [8.5 Revoke API Key (Dual-Layer: DB + Redis)](#85-revoke-api-key-dual-layer-db--redis)
   - [8.6 Verify Revoked API Key (Assert Immediate Rejection)](#86-verify-revoked-api-key-assert-immediate-rejection)
   - [8.7 Verify Expired API Key (Assert Expiration Rejection)](#87-verify-expired-api-key-assert-expiration-rejection)
   - [8.8 User Sign-Up (Triggers Async Verification Dispatch)](#88-user-sign-up-triggers-async-verification-dispatch)
   - [8.9 Resend Email Verification Token](#89-resend-email-verification-token)
   - [8.10 Confirm Email Verification (Atomic Consumption)](#810-confirm-email-verification-atomic-consumption)
   - [8.11 Reject Invalid / Consumed Email Verification Token](#811-reject-invalid--consumed-email-verification-token)
9. [Configuration Decoupling Matrix](#9-configuration-decoupling-matrix)
10. [Security & Compliance Architecture](#10-security--compliance-architecture)
11. [Verification & Proof of Correctness](#11-verification--proof-of-correctness)

---

## 🏛 1. High-Level Design (HLD)

The authentication subsystem sits at the boundary of incoming traffic, managing identity issuance, token lifecycle, and administrative credentials. The system decouples business workflows from transport gateways and data stores via strict Hexagonal architecture.

```mermaid
flowchart TD
    subgraph ClientLayer["Client Applications & SDKs"]
        SDK["Observability Node / Python SDK"]
        AdminUI["Management Portal / Web App"]
        CLI["Developer CLI / Pipeline Runner"]
    end

    subgraph APIGateway["REST Routing Layer (:3001)"]
        RestRouter["AuthRestV1Router<br/>Declarative Routing and Context"]
        RateLimiterMW["Adaptive Rate Limiter Middleware"]
    end

    subgraph CoreServices["Hexagonal Core: Domain Services"]
        ApiKeyService["ApiKeyDomainService<br/>TTL Enforcement and Revocation Logic"]
        UserAuthService["UserAuthDomainService<br/>Registration, Login and Verification"]
        NotificationService["NotificationDomainService<br/>Transactional Message Dispatcher"]
        Tracer["OpenTelemetry Tracer<br/>withSpan Instrumentation"]
    end

    subgraph DataAdapters["Persistence and In-Memory Ports"]
        PostgresRepo[("PostgreSQL / AlloyDB Omni<br/>auth_api_keys, auth_users")]
        RedisCache[("Redis Edge Cache Cluster<br/>auth:revoked_api_key, auth:denylist")]
    end

    subgraph MailerInfra["Pluggable Mailer Subsystem (MailerPort)"]
        MailerFactory["createMailer(AUTH_CONFIG.mailer)"]
        BaseRest["BaseRestMailerAdapter<br/>Fail-Fast Validation and Error Handling"]
        HttpClient["ScalableHttpClient<br/>Circuit Breaker, SSRF Guard, Retries"]
        SES["SesMailerAdapter<br/>SigV4 Signed REST"]
        SendGrid["SendgridMailerAdapter<br/>Bearer Token REST"]
        SMTP["SmtpMailerAdapter<br/>RFC 2045 TLS / STARTTLS"]
        Mock["MockMailerAdapter<br/>In-Memory Test Double"]
    end

    subgraph RemoteProviders["External Email Providers"]
        AWSSES["AWS SES v2 REST Endpoint"]
        SendGridAPI["SendGrid v3 REST Endpoint"]
        SMTPServer["Enterprise SMTP Server"]
    end

    ClientLayer -->|"HTTPS / REST"| APIGateway
    APIGateway --> RateLimiterMW
    RateLimiterMW --> RestRouter

    RestRouter --> ApiKeyService
    RestRouter --> UserAuthService

    ApiKeyService -->|"Store Key & Update Telemetry"| PostgresRepo
    ApiKeyService -->|"Push Revocation Cache O(1)"| RedisCache
    ApiKeyService --> Tracer

    UserAuthService -->|"Persist Users & Tokens"| PostgresRepo
    UserAuthService --> NotificationService

    NotificationService --> MailerFactory
    MailerFactory --> SES
    MailerFactory --> SendGrid
    MailerFactory --> SMTP
    MailerFactory --> Mock

    SES --> BaseRest
    SendGrid --> BaseRest
    BaseRest --> HttpClient

    HttpClient -->|"HTTPS SigV4"| AWSSES
    HttpClient -->|"HTTPS Bearer"| SendGridAPI
    SMTP -->|"Raw Socket TLS"| SMTPServer
```

---

## 🧩 2. Ports and Adapters (Hexagonal Architecture)

The system enforces strict boundary isolation. Domain services only communicate with typed interfaces (Ports). External integrations implement these ports as Adapters, allowing zero-code-change provider replacement.

```mermaid
classDiagram
    class MailerPort {
        <<interface>>
        +send(message: EmailMessage): Promise~MailerSendResult~
        +verify(): Promise~boolean~
    }

    class ICachePort {
        <<interface>>
        +get(key: string): Promise~string | null~
        +set(key: string, value: string, ttlSeconds: number): Promise~void~
        +delete(key: string): Promise~void~
    }

    class AuthRepositoryPort {
        <<interface>>
        +saveApiKey(key: ApiKeyRecord): Promise~void~
        +findApiKeyByHash(hash: string): Promise~ApiKeyRecord | null~
        +updateApiKeyUsage(keyId: string, timestampMs: number, ip: string): Promise~void~
        +revokeApiKey(keyId: string): Promise~void~
        +saveEmailVerificationToken(tokenHash: string, userId: string, email: string, expiresAtMs: number): Promise~void~
        +findEmailVerificationToken(tokenHash: string): Promise~EmailVerificationRecord | null~
        +markEmailVerified(tokenHash: string, userId: string): Promise~void~
    }

    class BaseRestMailerAdapter {
        <<abstract>>
        #httpClient: ScalableHttpClient
        +send(message: EmailMessage): Promise~MailerSendResult~
        #validateCredentials()* ValidationResult
        #buildPayload(message: EmailMessage)* RestPayloadConfig
        #parseSendResponse(response: HttpResponse)* MailerSendResult
    }

    class SesMailerAdapter {
        -region: string
        -accessKeyId: string
        -secretAccessKey: string
        #validateCredentials(): ValidationResult
        #buildPayload(message: EmailMessage): RestPayloadConfig
        #parseSendResponse(response: HttpResponse): MailerSendResult
        -computeSigV4Headers(...): Headers
    }

    class SendgridMailerAdapter {
        -apiKey: string
        #validateCredentials(): ValidationResult
        #buildPayload(message: EmailMessage): RestPayloadConfig
        #parseSendResponse(response: HttpResponse): MailerSendResult
    }

    class SmtpMailerAdapter {
        -host: string
        -port: number
        -secure: boolean
        -user: string
        -pass: string
        +send(message: EmailMessage): Promise~MailerSendResult~
        +verify(): Promise~boolean~
    }

    class MockMailerAdapter {
        +sentEmails: EmailMessage[]
        +send(message: EmailMessage): Promise~MailerSendResult~
        +verify(): Promise~boolean~
    }

    MailerPort <|.. BaseRestMailerAdapter
    MailerPort <|.. SmtpMailerAdapter
    MailerPort <|.. MockMailerAdapter
    BaseRestMailerAdapter <|-- SesMailerAdapter
    BaseRestMailerAdapter <|-- SendgridMailerAdapter
```

---

## 🔬 3. Low-Level Design (LLD) & Sequence Flows

### 3.1 API Key Engine: TTL Enforcement, Instant Revocation & Telemetry

The API key subsystem guarantees that high-privilege keys (`super_secret`) cannot be created without an explicit, bounded expiration timestamp. When verified, requests pass through edge cache denylists before updating database usage telemetry.

```mermaid
sequenceDiagram
    autonumber
    participant Client as Consumer / Admin
    participant Router as AuthRestV1Router
    participant Service as ApiKeyDomainService
    participant Redis as RedisCacheAdapter (ICachePort)
    participant DB as AuthRepositoryPort (PostgreSQL)

    Note over Client, DB: Phase 1: Key Creation with Strict Validation
    Client->>Router: POST /api/v1/auth/api-keys { key_type: 'super_secret', permissions, expires_at_ms }
    Router->>Service: generateApiKey(input)
    
    alt super_secret key without expires_at_ms
        Service-->>Router: throw ValidationError("expires_at_ms is required for super_secret keys")
        Router-->>Client: HTTP 400 Bad Request
    else expires_at_ms > 90 days from now
        Service-->>Router: throw ValidationError("super_secret key TTL cannot exceed 90 days")
        Router-->>Client: HTTP 400 Bad Request
    else Valid parameters
        Service->>Service: Generate raw key: ak_sec_<orgId>_<hex24>
        Service->>Service: Compute SHA-256 hash of raw key
        Service->>DB: saveApiKey(keyRecord)
        Service-->>Router: { rawKey, keyRecord }
        Router-->>Client: HTTP 201 Created
    end

    Note over Client, DB: Phase 2: Key Verification with Edge Revocation & Telemetry
    Client->>Router: POST /api/v1/auth/api-keys/verify { key, required_permission }
    Router->>Service: verifyApiKey(input)
    Service->>Service: Compute SHA-256 hash of incoming key
    Service->>DB: findApiKeyByHash(hash)

    alt Record not found or DB revoked = true
        Service-->>Router: throw ApiKeyRevokedError()
        Router-->>Client: HTTP 401 Unauthorized (API_KEY_REVOKED)
    end

    opt Check Redis Edge Revocation
        Service->>Redis: get("auth:revoked_api_key:" + keyRecord.key_id)
        alt Key present in Redis denylist
            Service-->>Router: throw ApiKeyRevokedError()
            Router-->>Client: HTTP 401 Unauthorized (API_KEY_REVOKED)
        end
    end

    alt Date.now() > keyRecord.expires_at_ms
        Service-->>Router: throw ApiKeyExpiredError()
        Router-->>Client: HTTP 401 Unauthorized (API_KEY_EXPIRED)
    end

    Service->>Service: Check permission match
    Service->>DB: updateApiKeyUsage(key_id, Date.now(), clientIp)
    Service-->>Router: { valid: true, authorized: true, record }
    Router-->>Client: HTTP 200 OK

    Note over Client, DB: Phase 3: Instant Revocation Propagation
    Client->>Router: POST /api/v1/auth/api-keys/:id/revoke
    Router->>Service: revokeApiKey(id)
    Service->>DB: revokeApiKey(id)
    opt Push to Edge Cache
        Service->>Redis: set("auth:revoked_api_key:" + id, "true", 7776000)
    end
    Service-->>Router: void
    Router-->>Client: HTTP 200 OK (Revoked)
```

---

### 3.2 Transactional Mailer: Fail-Fast Execution Pipeline

The `BaseRestMailerAdapter` enforces a strict 4-phase template method execution pipeline to protect system resources and reject invalid messages before performing network operations or socket allocation.

```mermaid
sequenceDiagram
    autonumber
    participant App as Application Layer
    participant Base as BaseRestMailerAdapter
    participant Impl as Concrete Adapter (SES / SendGrid)
    participant Http as ScalableHttpClient (@shared-infra/http)
    participant Ext as Upstream Mail Gateway

    App->>Base: send(emailMessage)

    rect rgb(255, 240, 240)
        Note over Base: Step 1: Fail-Fast Message Envelope Validation (Zero Cost)
        Base->>Base: validateEmailMessage(emailMessage)
        alt Invalid email syntax, missing subject, or both text/html empty
            Base-->>App: { success: false, error: "Validation Error: ..." }
        end
    end

    rect rgb(255, 248, 240)
        Note over Base, Impl: Step 2: Fail-Fast Credential Verification
        Base->>Impl: validateCredentials()
        alt Missing credentials (e.g. Empty API Key or AWS Secret)
            Impl-->>Base: { isValid: false, error: "Credentials missing" }
            Base-->>App: { success: false, error: "Credentials missing" }
        end
    end

    rect rgb(240, 248, 255)
        Note over Base, Http: Step 3: Payload Construction & Resilient Dispatch
        Base->>Impl: buildPayload(emailMessage)
        Impl->>Impl: Resolve endpoint from centralized mailer.config.ts
        Impl->>Impl: Format RFC 2045 MIME / SigV4 HMAC or SendGrid JSON
        Impl-->>Base: { url, body, headers, options }

        Base->>Http: post(url, body, headers, options)
        Http->>Ext: POST /endpoint (Subject to Circuit Breaker & Retries)
        Ext-->>Http: HTTP Response (Status, Body)
        Http-->>Base: { status, data }
    end

    rect rgb(240, 255, 240)
        Note over Base, Impl: Step 4: Response Parsing & Normalization
        Base->>Impl: parseSendResponse(httpResponse)
        alt 2xx Status Code
            Impl-->>Base: { success: true, messageId: "..." }
            Base-->>App: { success: true, messageId: "..." }
        else 4xx / 5xx Status Code
            Impl-->>Base: { success: false, error: "Upstream Error" }
            Base-->>App: { success: false, error: "Upstream Error" }
        end
    end
```

---

### 3.3 Email Verification: Sign-Up to Atomic Confirmation

```mermaid
sequenceDiagram
    autonumber
    participant User as End User
    participant Router as AuthRestV1Router
    participant Auth as UserAuthDomainService
    participant Notif as NotificationDomainService
    participant Mailer as MailerPort
    participant DB as PostgreSQL / AlloyDB

    User->>Router: POST /api/v1/auth/sign-up { email, password, name, org_name }
    Router->>Auth: signUp(input)
    Auth->>DB: createOrganizationAndUser(userRecord)

    rect rgb(245, 245, 255)
        Note over Auth, Mailer: Asynchronous Background Verification Dispatch
        Auth--)Auth: dispatchEmailVerificationAsync(userId, email, name)
        Auth->>Auth: Generate unguessable token: evf_<random32>
        Auth->>Auth: Compute SHA-256(token)
        Auth->>DB: saveEmailVerificationToken(tokenHash, userId, email, expiresAtMs)
        Auth->>Notif: sendEmailVerification(email, name, rawToken)
        Notif->>Mailer: send(EmailMessage)
    end

    Auth-->>Router: { token, user, payload }
    Router-->>User: HTTP 201 Created

    Note over User, DB: Confirmation Phase
    User->>Router: POST /api/v1/auth/verify-email { token: "evf_..." }
    Router->>Auth: verifyEmail(token)
    Auth->>Auth: Compute SHA-256(token)
    Auth->>DB: findEmailVerificationToken(tokenHash)

    alt Token not found, expired, or already used
        Auth-->>Router: throw ValidationError("Invalid or expired email verification token")
        Router-->>User: HTTP 400 Bad Request
    else Valid Unused Token
        Auth->>DB: markEmailVerified(tokenHash, userId)
        Note over DB: SQL Transaction: UPDATE auth_email_verifications SET used=true AND UPDATE auth_users SET email_verified=true
        Auth-->>Router: void
        Router-->>User: HTTP 200 OK { status: 'success', data: { verified: true } }
    end
```

---

### 3.4 SMTP Wire Protocol Exchange (RFC 5321 & RFC 3207)

When `SmtpMailerAdapter` is engaged, it connects via TCP socket, negotiates transport layer security via STARTTLS, executes authentication, and streams standard MIME data:

```mermaid
sequenceDiagram
    autonumber
    participant Client as SmtpMailerAdapter (Node.js net/tls)
    participant Server as MTA / SMTP Server (Port 587)

    Client->>Server: TCP SYN / Connect
    Server-->>Client: TCP ACK + 220 mail.domain.com ESMTP Postfix
    Client->>Server: EHLO client.local
    Server-->>Client: 250-STARTTLS, 250-AUTH LOGIN PLAIN, 250 8BITMIME
    
    rect rgb(240, 248, 255)
        Note over Client, Server: RFC 3207 STARTTLS Upgrade
        Client->>Server: STARTTLS
        Server-->>Client: 220 2.0.0 Ready to start TLS
        Client->>Server: TLS Handshake (ClientHello, Cert Verification)
        Server-->>Client: TLS Session Established
        Client->>Server: EHLO client.local (Encrypted)
        Server-->>Client: 250-AUTH LOGIN PLAIN, 250 OK
    end

    rect rgb(255, 248, 240)
        Note over Client, Server: SASL Authentication
        Client->>Server: AUTH LOGIN
        Server-->>Client: 334 VXNlcm5hbWU6 (base64 "Username:")
        Client->>Server: base64(SMTP_USER)
        Server-->>Client: 334 UGFzc3dvcmQ6 (base64 "Password:")
        Client->>Server: base64(SMTP_PASS)
        Server-->>Client: 235 2.7.0 Authentication successful
    end

    rect rgb(240, 255, 240)
        Note over Client, Server: RFC 5321 Mail Transaction
        Client->>Server: MAIL FROM:<sender@domain.com>
        Server-->>Client: 250 2.1.0 Ok
        Client->>Server: RCPT TO:<recipient@domain.com>
        Server-->>Client: 250 2.1.5 Ok
        Client->>Server: DATA
        Server-->>Client: 354 End data with CRLF.CRLF
        Client->>Server: RFC 2045 Multipart/Alternative Payload
        Server-->>Client: 250 2.0.0 Ok: queued as 4X8Z910
        Client->>Server: QUIT
        Server-->>Client: 221 2.0.0 Bye
    end
```

---

## 🔄 4. Finite State Machines & Lifecycle Transitions

### 4.1 API Key Lifecycle State Machine

```mermaid
stateDiagram-v2
    [*] --> Active : generateApiKey with TTL <= 90 days
    
    state Active {
        [*] --> Idle
        Idle --> Verified : POST /api/keys/verify
        Verified --> Idle : Update Telemetry (last_used_at_ms, ip)
    }

    Active --> Revoked : POST /api/keys/id/revoke (DB and Redis Denylist)
    Active --> Expired : now > expires_at_ms (TTL Exceeded)

    Revoked --> [*] : HTTP 401 API_KEY_REVOKED
    Expired --> [*] : HTTP 401 API_KEY_EXPIRED
```

---

### 4.2 Email Verification Token Lifecycle State Machine

```mermaid
stateDiagram-v2
    [*] --> Issued : signUp or resendVerification (24h TTL)
    
    Issued --> Consumed : POST /verify-email (Atomic Transaction)
    Issued --> Expired : now > expires_at_ms (24h Window)
    Issued --> Superseded : POST /resend-verification (New Token Issued)

    Consumed --> [*] : Verified State Confirmed
    Expired --> [*] : Rejection HTTP 400
    Superseded --> [*] : Obsolete
```

---

## 📜 5. Open Standards & Protocol Specifications

### 5.1 MIME RFC 2045 & RFC 5322 Multipart Architecture

All transactional emails generated by `@observability/auth` assemble RFC 2045 / RFC 5322 compliant `multipart/alternative` message streams:

```
From: Observability Platform <no-reply@observability.internal>
To: recipient@company.com
Subject: Verify Your Account
Date: Sat, 19 Sep 2026 10:15:00 GMT
Message-ID: <3d5a2f8c-9b1e-4c7a-8b2d-1a2b3c4d5e6f@observability.internal>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="----=_Part_9f8e7d6c5b4a3a2b1"

------=_Part_9f8e7d6c5b4a3a2b1
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: quoted-printable

Please verify your account by following this link:
https://app.observability.internal/verify?token=3Devf_bplwxrme3go

------=_Part_9f8e7d6c5b4a3a2b1
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html>
<html>
<body>
  <h2>Welcome to Observability Platform</h2>
  <p>Please click below to verify your account:</p>
  <a href=3D"https://app.observability.internal/verify?token=3Devf_bplwxrme3go">Verify Email</a>
</body>
</html>

------=_Part_9f8e7d6c5b4a3a2b1--
```

---

### 5.2 AWS Signature Version 4 (SigV4) Cryptographic Pipeline

The `SesMailerAdapter` signs requests natively with zero AWS SDK dependencies using HMAC-SHA256 (RFC 2104):

```mermaid
flowchart TD
    subgraph Step1["1. Canonical Request"]
        CR["POST /v2/email/outbound-emails<br/>SignedHeaders: host;x-amz-date<br/>Payload: SHA-256(RawBody)"]
        HashedCR["SHA-256(Canonical Request)"]
        CR --> HashedCR
    end

    subgraph Step2["2. String to Sign"]
        STS["Algorithm: AWS4-HMAC-SHA256<br/>Scope: Date/Region/ses/aws4_request<br/>HashedCanonicalRequest"]
        HashedCR --> STS
    end

    subgraph Step3["3. Derived Signing Key"]
        KSecret["kSecret: AWS4 + SecretAccessKey"]
        KDate["kDate: HMAC-SHA256(kSecret, Date)"]
        KRegion["kRegion: HMAC-SHA256(kDate, Region)"]
        KService["kService: HMAC-SHA256(kRegion, ses)"]
        KSigning["kSigning: HMAC-SHA256(KService, aws4_request)"]
        KSecret --> KDate --> KRegion --> KService --> KSigning
    end

    subgraph Step4["4. Signature and Authorization Header"]
        CalcSig["Signature = Hex(HMAC-SHA256(kSigning, StringToSign))"]
        AuthHeader["Authorization: AWS4-HMAC-SHA256<br/>Credential=Key/Scope, Signature=..."]
        STS & KSigning --> CalcSig --> AuthHeader
    end
```

---

### 5.3 ScalableHttpClient 8-Step Resilience Pipeline

```mermaid
flowchart LR
    P1["1. Admission Control<br/>Semaphore Token"] --> P2["2. Context Isolation<br/>Tenant Propagation"]
    P2 --> P3["3. SSRF Guard<br/>DNS IP Validation"]
    P3 --> P4["4. Tenant Rate Limit<br/>Token Bucket"]
    P4 --> P5["5. Singleflight<br/>Coalescing Requests"]
    P5 --> P6["6. Cache Evaluation<br/>RFC 7234"]
    P6 --> P7["7. Circuit Breaker<br/>Fail-Fast Protection"]
    P7 --> P8["8. Network Dispatch<br/>Exponential Jitter"]
```

---

## 🗄 6. Relational Database Schema & Migrations

```mermaid
flowchart TD
    subgraph Organizations["auth_organizations"]
        org_id["id (PK): varchar"]
        org_name["name: varchar"]
        org_slug["slug: varchar"]
        org_created["created_at: timestamp"]
    end

    subgraph Users["auth_users"]
        user_id["id (PK): varchar"]
        user_org["org_id (FK): varchar"]
        user_email["email: varchar"]
        user_verified["email_verified: boolean"]
        user_role["role: varchar"]
        user_created["created_at: timestamp"]
    end

    subgraph ApiKeys["auth_api_keys"]
        key_id["key_id (PK): varchar"]
        key_org["org_id (FK): varchar"]
        key_type["key_type: varchar"]
        key_hash["key_hash (UK): varchar"]
        key_expires["expires_at_ms: bigint"]
        key_used["last_used_at_ms: bigint"]
        key_ip["last_used_ip: varchar"]
        key_revoked["revoked: boolean"]
    end

    subgraph EmailVerifications["auth_email_verifications"]
        token_hash["token_hash (PK): varchar"]
        verif_user["user_id (FK): varchar"]
        verif_email["email: varchar"]
        verif_expires["expires_at_ms: bigint"]
        verif_used["used: boolean"]
    end

    subgraph AuditLogs["auth_audit_logs"]
        audit_id["id (PK): varchar"]
        audit_user["user_id (FK): varchar"]
        audit_event["event_type: varchar"]
        audit_time["timestamp_ms: bigint"]
    end

    Organizations -->|"1 : N (members)"| Users
    Organizations -->|"1 : N (scopes)"| ApiKeys
    Users -->|"1 : N (verifications)"| EmailVerifications
    Users -->|"1 : N (audit_records)"| AuditLogs
```

### Migration 0007: API Key Expiration & Usage Telemetry

```sql
-- Migration: 0007_add_api_key_expiration_and_usage.sql
ALTER TABLE auth_api_keys 
ADD COLUMN IF NOT EXISTS expires_at_ms BIGINT,
ADD COLUMN IF NOT EXISTS last_used_at_ms BIGINT,
ADD COLUMN IF NOT EXISTS last_used_ip VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_auth_api_keys_expires_at ON auth_api_keys(expires_at_ms);
CREATE INDEX IF NOT EXISTS idx_auth_api_keys_revoked ON auth_api_keys(revoked);
```

### Migration 0008: Email Verification Tokens Table

```sql
-- Migration: 0008_create_email_verifications_table.sql
CREATE TABLE IF NOT EXISTS auth_email_verifications (
    token_hash VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_auth_email_verifications_user_id ON auth_email_verifications(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_email_verifications_email ON auth_email_verifications(email);
CREATE INDEX IF NOT EXISTS idx_auth_email_verifications_expires_at ON auth_email_verifications(expires_at_ms);

ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE;
```

---

## 📡 7. Distributed Observability & TraceQL Queries

Every operation is instrumented using OpenTelemetry spans. The span hierarchy links incoming HTTP requests directly to domain logic, cache queries, and outbound HTTP/SMTP dispatches:

```mermaid
flowchart TD
    Span1["Span 1: HTTP POST /api/v1/auth/api-keys/verify"]
    Span2["Span 2: ApiKeyDomainService.verifyApiKey"]
    Span3["Span 3: RedisCacheAdapter.get"]
    Span4["Span 4: RealPostgresAuthAdapter.updateApiKeyUsage"]

    Span1 --> Span2
    Span2 --> Span3
    Span2 --> Span4
```

### TraceQL Debugging Queries for Grafana Tempo

```traceql
# 1. Find all rejected API key verification attempts due to expiration
{ span.name = "ApiKeyDomainService.verifyApiKey" && status = error && api_key.status = "expired" }

# 2. Track revoked API keys blocked by Redis edge cache
{ span.name = "ApiKeyDomainService.verifyApiKey" && api_key.revocation_source = "redis_cache" }

# 3. Detect outbound mailer failures and network retries
{ span.name = "SesMailerAdapter.send" && status = error }

# 4. Monitor email verification latency end-to-end
{ span.name = "UserAuthDomainService.verifyEmail" }
```

---

## 💻 8. Comprehensive API Curl Reference & Protocol Payloads

### 8.1 Create Ephemeral super_secret API Key (Mandatory TTL)

```bash
# Set expiration 30 days from now (epoch ms)
EXPIRES_AT_MS=$(( $(date +%s%3N) + 30 * 86400000 ))

curl -s -X POST "http://localhost:3001/api/v1/auth/api-keys" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <VALID_ADMIN_JWT_TOKEN>" \
  -H "x-request-id: req-sec-create-001" \
  -H "x-tenant-id: org_alpha_01" \
  -d '{
    "org_id": "org_alpha_01",
    "name": "Production Ingestion Pipeline Key",
    "key_type": "super_secret",
    "permissions": ["admin:all", "traces:write", "metrics:write"],
    "expires_at_ms": '"${EXPIRES_AT_MS}"'
  }'
```

#### Response Envelope: `201 Created`
```json
{
  "status": "success",
  "message": "API key successfully created",
  "data": {
    "rawKey": "ak_sec_org_alpha_01_a9f8b7c6d5e4f3a2b1c0d9e8",
    "keyRecord": {
      "key_id": "key_7a8b9c0d",
      "org_id": "org_alpha_01",
      "key_type": "super_secret",
      "key_hash": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
      "prefix": "ak_sec_",
      "name": "Production Ingestion Pipeline Key",
      "permissions": ["admin:all", "traces:write", "metrics:write"],
      "created_at_ms": 1789812000000,
      "revoked": false,
      "expires_at_ms": 1792404000000,
      "last_used_at_ms": null,
      "last_used_ip": null
    }
  },
  "error": null
}
```

---

### 8.2 Reject super_secret Key Missing TTL

```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/api-keys" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <VALID_ADMIN_JWT_TOKEN>" \
  -d '{
    "org_id": "org_alpha_01",
    "name": "Invalid Ephemeral Key",
    "key_type": "super_secret",
    "permissions": ["admin:all"]
  }'
```

#### Response Envelope: `400 Bad Request`
```json
{
  "status": "error",
  "message": "expires_at_ms is required for super_secret keys",
  "data": null,
  "error": {
    "code": "VALIDATION_ERROR",
    "details": "expires_at_ms is required for super_secret keys"
  }
}
```

---

### 8.3 Reject super_secret Key Exceeding 90-Day Max TTL

```bash
# 91 days into future
EXPIRES_TOO_FAR=$(( $(date +%s%3N) + 91 * 86400000 ))

curl -s -X POST "http://localhost:3001/api/v1/auth/api-keys" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <VALID_ADMIN_JWT_TOKEN>" \
  -d '{
    "org_id": "org_alpha_01",
    "name": "Excessive TTL Key",
    "key_type": "super_secret",
    "permissions": ["admin:all"],
    "expires_at_ms": '"${EXPIRES_TOO_FAR}"'
  }'
```

#### Response Envelope: `400 Bad Request`
```json
{
  "status": "error",
  "message": "super_secret key TTL cannot exceed 90 days",
  "data": null,
  "error": {
    "code": "VALIDATION_ERROR",
    "details": "super_secret key TTL cannot exceed 90 days"
  }
}
```

---

### 8.4 Verify API Key & Record Usage Telemetry

```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/api-keys/verify" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 198.51.100.77" \
  -d '{
    "key": "ak_sec_org_alpha_01_a9f8b7c6d5e4f3a2b1c0d9e8",
    "required_permission": "traces:write"
  }'
```

#### Response Envelope: `200 OK`
```json
{
  "status": "success",
  "message": "API key verified",
  "data": {
    "valid": true,
    "authorized": true,
    "record": {
      "key_id": "key_7a8b9c0d",
      "org_id": "org_alpha_01",
      "key_type": "super_secret",
      "name": "Production Ingestion Pipeline Key",
      "permissions": ["admin:all", "traces:write", "metrics:write"],
      "expires_at_ms": 1792404000000,
      "last_used_at_ms": 1789812050000,
      "last_used_ip": "198.51.100.77"
    }
  },
  "error": null
}
```

---

### 8.5 Revoke API Key (Dual-Layer: DB + Redis)

```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/api-keys/key_7a8b9c0d/revoke" \
  -H "Authorization: Bearer <VALID_ADMIN_JWT_TOKEN>"
```

#### Response Envelope: `200 OK`
```json
{
  "status": "success",
  "message": "API key revoked",
  "data": null,
  "error": null
}
```

---

### 8.6 Verify Revoked API Key (Assert Immediate Rejection)

```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/api-keys/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "key": "ak_sec_org_alpha_01_a9f8b7c6d5e4f3a2b1c0d9e8",
    "required_permission": "traces:write"
  }'
```

#### Response Envelope: `401 Unauthorized`
```json
{
  "status": "error",
  "message": "API key has been revoked or invalid",
  "data": null,
  "error": {
    "code": "API_KEY_REVOKED",
    "details": "API key has been revoked or invalid"
  }
}
```

---

### 8.7 Verify Expired API Key (Assert Expiration Rejection)

```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/api-keys/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "key": "ak_sec_org_expired_example_key",
    "required_permission": "traces:write"
  }'
```

#### Response Envelope: `401 Unauthorized`
```json
{
  "status": "error",
  "message": "API key has expired",
  "data": null,
  "error": {
    "code": "API_KEY_EXPIRED",
    "details": "API key has expired"
  }
}
```

---

### 8.8 User Sign-Up (Triggers Async Verification Dispatch)

```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/sign-up" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "lead.architect@company.com",
    "password": "SuperSecretPassword123!",
    "name": "Lead Architect",
    "org_name": "Enterprise Observability Org"
  }'
```

#### Response Envelope: `201 Created`
```json
{
  "status": "success",
  "message": "User registered successfully",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "id": "usr_99887766",
      "org_id": "org_55443322",
      "email": "lead.architect@company.com",
      "name": "Lead Architect",
      "role": "owner",
      "blocked": false,
      "email_verified": false,
      "user_permissions": ["*"]
    }
  },
  "error": null
}
```

---

### 8.9 Resend Email Verification Token

```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/resend-verification" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "lead.architect@company.com"
  }'
```

#### Response Envelope: `200 OK`
```json
{
  "status": "success",
  "message": "Verification email resent",
  "data": {
    "sent": true
  },
  "error": null
}
```

---

### 8.10 Confirm Email Verification (Atomic Consumption)

```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/verify-email" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "evf_bplwxrme3go771122"
  }'
```

#### Response Envelope: `200 OK`
```json
{
  "status": "success",
  "message": "Email verified successfully",
  "data": {
    "verified": true
  },
  "error": null
}
```

---

### 8.11 Reject Invalid / Consumed Email Verification Token

```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/verify-email" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "evf_already_consumed_token"
  }'
```

#### Response Envelope: `400 Bad Request`
```json
{
  "status": "error",
  "message": "Invalid or expired email verification token",
  "data": null,
  "error": {
    "code": "VALIDATION_ERROR",
    "details": "Invalid or expired email verification token"
  }
}
```

---

## ⚙️ 9. Configuration Decoupling Matrix

All endpoints, paths, and provider parameters are externalized in `src/config/mailer.config.ts` and loaded through environment configuration:

| Configuration Path | Environment Variable | Default Setting | Description & Upstream Contract |
|---|---|---|---|
| `mailer.provider` | `MAILER_PROVIDER` | `mock` (or `ses`, `sendgrid`, `smtp`) | Active mailer provider selection |
| `mailer.from` | `MAILER_FROM` | `no-reply@observability.internal` | Standard envelope sender identity |
| `mailer.ses.region` | `AWS_REGION` | `us-east-1` | AWS SES target deployment region |
| `mailer.ses.endpointTemplate` | `AWS_SES_ENDPOINT_TEMPLATE` | `https://email.{region}.amazonaws.com` | Dynamically interpolated SES endpoint |
| `mailer.ses.sendPath` | `AWS_SES_SEND_PATH` | `/v2/email/outbound-emails` | SES v2 Raw MIME dispatch path |
| `mailer.ses.accountPath` | `AWS_SES_ACCOUNT_PATH` | `/v2/email/account` | SES connectivity & quota verification path |
| `mailer.sendgrid.apiUrl` | `SENDGRID_API_URL` | `https://api.sendgrid.com` | Base URL for SendGrid REST gateway |
| `mailer.sendgrid.sendPath` | `SENDGRID_SEND_PATH` | `/v3/mail/send` | SendGrid v3 transactional dispatch path |
| `mailer.sendgrid.verifyPath` | `SENDGRID_VERIFY_PATH` | `/v3/user/profile` | SendGrid API key verification path |
| `mailer.smtp.host` | `SMTP_HOST` | `localhost` | Corporate / relay SMTP host |
| `mailer.smtp.port` | `SMTP_PORT` | `587` | Standard submission port (STARTTLS) |
| `mailer.smtp.secure` | `SMTP_SECURE` | `false` | `true` for Port 465 SSL, `false` for 587 STARTTLS |

---

## 🛡 10. Security & Compliance Architecture

1. **Strict Cryptographic Hashing at Rest**:
   - Neither API key secrets nor email verification tokens are stored in plaintext. Raw values exist in memory solely during creation and dispatch.
   - Database tables store SHA-256 hashes (`key_hash` and `token_hash`).
   - Passwords use Argon2id with recommended memory and parallelism parameters.

2. **Defense-in-Depth Instant Revocation**:
   - Database persistence provides auditable and durable record of revocation.
   - Redis edge cache stores revoked key IDs (`auth:revoked_api_key:{id}`) with 90-day TTL matching maximum key lifespan, enabling sub-millisecond rejection before database queries.

3. **Concurrency & Double-Spend Prevention**:
   - Email verification operates inside an ACID transaction (`BEGIN ... COMMIT`).
   - The query checks `WHERE token_hash = $1 AND used = FALSE AND expires_at_ms > $2`.
   - Token consumption sets `used = TRUE` simultaneously updating `auth_users.email_verified = TRUE`.

4. **Resource Exhaustion & SSRF Protection**:
   - `validateEmailMessage` executes fail-fast regex and boundary validation before computing hashes or initiating network requests.
   - `ScalableHttpClient` enforces egress IP filtering, preventing internal infrastructure SSRF targeting link-local metadata endpoints (`169.254.169.254`).

---

## 🧪 11. Verification & Proof of Correctness

- **TypeScript Compilation**: `npm run typecheck` passes with **0 errors**.
- **Complete Test Suite**: **16 test files / 86 tests passed (0 failed)**.
- **Dedicated Mailer Tests**: 22 unit tests in `mailer.test.ts` verifying fail-fast guards, SigV4 signing, SendGrid formatting, SMTP message creation, and factory provider fallbacks.
- **Contract Integrity**: OpenAPI v1 contract tests passing (`tests/contract/auth-openapi.test.ts`).
- **Database E2E Verification**: All 37 live API endpoints validated with live PostgreSQL/AlloyDB Omni (port 5432) and Redis (port 6379) via `tests/e2e/test-curl-endpoints.sh`.

## Execution Flow (Call Stack Tree)

```text
createServer(listener: (req: IncomingMessage, res: ServerResponse) => void): Server
└── runWithHttpTracing(req: IncomingMessage, res: ServerResponse, fn: () => Promise<void>): Promise<void>
    └── dispatch(method: string, path: string, body: unknown, headers: Record<string, string>): Promise<RouteDispatchResult>
        ├── matchRoute(method: string, path: string): { rule: RouteRule, params: Record<string, string> } | null
        ├── handler(ctx: RouteContext): Promise<ApiKeyGeneratedResult>
        │   createApiKey(orgId: string, input: CreateApiKeyInput): Promise<ApiKeyGeneratedResult>
        │   ├── generateSecureRandomToken(prefix: string, length: number): string
        │   ├── hashApiKey(token: string): string
        │   ├── insertApiKey(hashedKey: string, meta: ApiKeyMeta): Promise<ApiKeyRecord>
        │   └── sendNotificationMail(to: string, template: EmailTemplate): Promise<void>
        ├── createSuccessResponse(data: ApiKeyGeneratedResult, message: string, meta: ResponseMeta, statusCode: number): ApiResponse<ApiKeyGeneratedResult>
        └── end(chunk: string): ServerResponse

// Type Reference:
// ApiResponse<T>      = { success: boolean, statusCode: number, message: string, data: T, meta: ResponseMeta }
// RouteDispatchResult = { statusCode: number, payload: ApiResponse<ApiKeyGeneratedResult>, headers: Record<string, string> }
```

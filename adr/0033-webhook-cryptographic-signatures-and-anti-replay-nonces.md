# ADR 0033: Webhook Cryptographic Signatures (RFC 2104 HMAC-SHA256), Anti-Replay Nonces & Delivery Ledger

- **Status**: Accepted
- **Date**: 2026-10-15
- **Author**: Platform Architecture Team
- **Area**: Event Delivery, Cryptographic Signatures, Anti-Replay Nonces, Webhook Perimeter Defense, Zero-Trust
- **Standards**: [RFC 2104 (HMAC: Keyed-Hashing for Message Authentication)](https://datatracker.ietf.org/doc/html/rfc2104), [RFC 2898 (PKCS #5: Password-Based Cryptography)](https://datatracker.ietf.org/doc/html/rfc2898), [RFC 8941 (Structured Field Values for HTTP)](https://datatracker.ietf.org/doc/html/rfc8941), [OWASP ASVS v4.0.3 §13.2 (API Verification)](https://owasp.org/www-project-application-security-verification-standard/)

---

## 🎯 1. Context, Threat Modeling & Business Drivers

Security, audit, and identity lifecycle events (e.g. `user.created`, `role.assigned`, `security.passkey_cloned`, `account.locked`) must be reliably dispatched to downstream consumer endpoints (SIEM collectors, HRIS directories, IT automation platforms, and customer API gateways).

Dispatching unauthenticated or unscheduled HTTP POST payloads over the public internet exposes consumers to critical vulnerabilities:
1. **Adversary Payload Forgery**: Without cryptographic signatures, an attacker can dispatch fake webhook requests mimicking `@observability/auth`, forging administrative role escalations or triggering fraudulent account deletions in downstream systems.
2. **Replay Attacks**: An eavesdropper or intermediate network interceptor can capture a legitimate webhook payload and replay it hours or days later (e.g. replaying an account suspension event to cause unauthorized downtime).
3. **Payload Tampering in Transit**: Modifying JSON attributes (such as changing an assigned role or user permissions) between the auth service and consumer endpoint.
4. **Timing Attack Vulnerabilities in Signature Verification**: Naive string comparisons (`signature === expected`) leak byte-matching timing information, enabling attackers to deduce cryptographic signatures byte by byte.

---

## 🏗️ 2. Architectural Decision & Technical Principles

To guarantee authenticated, tamper-proof, and non-replayable event delivery:

### 1. Cryptographic HMAC-SHA256 Signatures
Every outbound webhook includes standardized cryptographic headers:
- `X-Auth-Signature`: `t={timestamp_epoch_ms},v1={hmac_sha256_hex}`
- `X-Auth-Nonce`: `{uuid_v7}` (unique per dispatch attempt)

### 2. Canonical Signature Representation
The HMAC-SHA256 is computed over a canonical payload string:
$$\text{canonical} = \text{"t."} + \text{timestamp} + \text{".n."} + \text{nonce} + \text{".b."} + \text{rawJsonBody}$$
This binds the timestamp, nonce, and full payload to the tenant's shared cryptographic secret (`whsec_...`).

### 3. Anti-Replay Drift Window & Nonce Cache
- Consumers reject webhooks if $|\text{current\_time} - \text{timestamp}| > 300\text{ seconds}$ (strict 5-minute drift window).
- Nonces are tracked in Redis with a 360-second TTL to guarantee absolute single-delivery execution.

### 4. Constant-Time Timing-Safe Comparison
All signature verifications use `crypto.timingSafeEqual` over fixed 32-byte binary buffers to eliminate side-channel timing leaks.

---

## 📊 3. Database Schema Specification (`auth_webhook_subscriptions` & `auth_webhook_deliveries`)

In strict compliance with [05-db-writing-rules.md](file:///home/btpl-lap-22/live/llm-obs-node-packages/llm-obs-policies/rules/folder-structure/05-db-writing-rules.md):

```mermaid
erDiagram
    AUTH_ORGANIZATIONS ||--o{ AUTH_WEBHOOK_SUBSCRIPTIONS : "scopes (1:N)"
    AUTH_WEBHOOK_SUBSCRIPTIONS ||--o{ AUTH_WEBHOOK_DELIVERIES : "records (1:N)"

    AUTH_WEBHOOK_SUBSCRIPTIONS {
        varchar(64) id PK "whsub_uuidv7"
        varchar(64) public_id UK "pub_whsub_uuidv7"
        varchar(64) org_id FK "REFERENCES auth_organizations(id)"
        varchar(512) target_url "Validated HTTPS endpoint"
        varchar(128) secret_hash "SHA-256 of signing secret"
        varchar(64) secret_prefix "whsec_ prefix for identification"
        jsonb subscribed_events "Array of event types"
        boolean active "Enabled/disabled state"
        bigint version "Optimistic locking version counter"
        bigint created_at_ms
        bigint updated_at_ms
        timestamp deleted_at "Soft delete marker"
    }

    AUTH_WEBHOOK_DELIVERIES {
        varchar(64) id PK "whdel_uuidv7"
        varchar(64) public_id UK "pub_whdel_uuidv7"
        varchar(64) subscription_id FK "REFERENCES auth_webhook_subscriptions(id)"
        varchar(64) org_id FK "REFERENCES auth_organizations(id)"
        varchar(64) event_type "e.g. role.assigned"
        varchar(64) nonce UK "Cryptographic dispatch nonce"
        int response_status "HTTP status code (200, 500, etc.)"
        bigint execution_duration_ms "Latency metric"
        boolean success "Delivery outcome flag"
        varchar(512) failure_reason "Error message on drop"
        bigint delivered_at_ms "Append-only timestamp"
    }
```

---

## 🔄 4. Webhook Dispatch & Verification Lifecycle State Machine

```mermaid
stateDiagram-v2
    [*] --> EventTriggered: Domain event emitted (e.g. role.assigned)
    
    state EventTriggered {
        [*] --> QueryActiveSubscriptions: SELECT WHERE org_id = $1 AND active = TRUE
        QueryActiveSubscriptions --> SubscriptionFound: Active subscribers exist
        QueryActiveSubscriptions --> ZeroSubscribers: No subscriptions configured
    }

    ZeroSubscribers --> [*]
    
    SubscriptionFound --> SignPayload: Generate nonce (UUIDv7) + timestamp (Date.now())
    
    state SignPayload {
        [*] --> Canonicalize: "t." + t + ".n." + nonce + ".b." + body
        Canonicalize --> ComputeHMAC: crypto.createHmac('sha256', secret)
        ComputeHMAC --> HeadersFormed: Set X-Auth-Signature & X-Auth-Nonce
    }

    HeadersFormed --> OutboundDispatch: HTTP POST target_url (bounded 5000ms timeout)
    
    state OutboundDispatch {
        [*] --> ResponseEvaluated
        ResponseEvaluated --> DeliverySucceeded: 2xx response code
        ResponseEvaluated --> DeliveryFailed: 4xx/5xx or timeout
    }

    DeliverySucceeded --> LedgerLogged: INSERT INTO auth_webhook_deliveries (success=true)
    DeliveryFailed --> LedgerLogged: INSERT INTO auth_webhook_deliveries (success=false)
    LedgerLogged --> [*]
```

---

## 🔄 5. End-to-End Consumer Verification Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Service as WebhookDispatchService
    participant Consumer as Enterprise Consumer API Gateway
    participant Verifier as WebhookSignatureVerifier
    participant Cache as Redis Nonce Cache

    Service->>Consumer: POST https://consumer.io/webhooks<br/>Headers: X-Auth-Signature, X-Auth-Nonce
    Consumer->>Verifier: verifyWebhookSignature(body, signatureHeader, nonceHeader, secret)
    Verifier->>Verifier: Parse t & v1 from X-Auth-Signature
    alt Timestamp Drift > 300 seconds
        Verifier-->>Consumer: Reject: E_WEBHOOK_TIMESTAMP_EXPIRED (400)
    else Timestamp Valid
        Verifier->>Cache: SET auth:webhook:nonce:{nonce} 1 NX EX 360
        alt Nonce Already Exists in Cache
            Cache-->>Verifier: NULL (Key exists)
            Verifier-->>Consumer: Reject: E_WEBHOOK_REPLAY_DETECTED (409)
        else Nonce Fresh
            Cache-->>Verifier: OK (Key set)
            Verifier->>Verifier: Compute expectedHMAC over canonical string
            Verifier->>Verifier: crypto.timingSafeEqual(expected, incoming)
            alt Signature Mismatch
                Verifier-->>Consumer: Reject: E_WEBHOOK_SIGNATURE_INVALID (401)
            else Signature Valid
                Verifier-->>Consumer: Verification Succeeded (Allow Execution)
                Consumer-->>Service: HTTP 200 OK
            end
        end
    end
```

---

## 🛡 6. Implementation Invariants & Clean Code Standards

- **Functions & Classes**: Adheres strictly to [4-functions-and-classes-writing-rule.md](file:///home/btpl-lap-22/live/llm-obs-node-packages/llm-obs-policies/rules/folder-structure/4-functions-and-classes-writing-rule.md) (stateless service, zero inline comments, constructor dependency injection, explicit `try/catch/finally` span ownership).
- **Shared Code Discipline**: Conforms to [3.shared.code.writing.rule.md](file:///home/btpl-lap-22/live/llm-obs-node-packages/llm-obs-policies/rules/folder-structure/3.shared.code.writing.rule.md) with pure cryptographic signing functions in `src/shared/utils/`.
- **API Response Envelopes**: Complies with [2-apis.writing.rule.md](file:///home/btpl-lap-22/live/llm-obs-node-packages/llm-obs-policies/rules/folder-structure/2-apis.writing.rule.md) with standardized envelopes (`success`, `statusCode`, `data`, `meta`).
- **Database Writing Rules**: Migration `0026_create_auth_webhook_subscriptions.sql` strictly follows [05-db-writing-rules.md](file:///home/btpl-lap-22/live/llm-obs-node-packages/llm-obs-policies/rules/folder-structure/05-db-writing-rules.md).

# ADR 0028: NIST SP 800-63B Password History Enforcement, FIFO Eviction & EDR/SIEM Credential Recycling Telemetry

- **Status**: Accepted
- **Date**: 2026-10-15
- **Author**: Platform Architecture Team
- **Area**: Credential Lifecycle, Password Security, NIST Compliance, Anti-Recycling & EDR/SIEM Threat Intelligence
- **Standards**: [NIST SP 800-63B Section 5.1.1.2 (Memorized Secret Verifiers)](https://pages.nist.gov/800-63-3/sp800-63b.html#sec5112), [OWASP ASVS v4.0.3 Chapter 2 (Authentication Verification)](https://owasp.org/www-project-application-security-verification-standard/), [RFC 9106 (Argon2 Memory-Hard Function)](https://datatracker.ietf.org/doc/html/rfc9106)

---

## 🎯 1. Context, Threat Modeling & Business Drivers

When organizations mandate periodic password rotation or when users trigger self-service recovery after forgotten credentials, human psychology defaults to the path of least cognitive resistance. Users oscillate between two or three memorized passwords, append incrementing numerical suffixes (`Autumn2024!`, `Winter2024!`), or revert to a previously compromised secret as soon as compliance alarms subside.

### 1.1 Threat Vectors Addressed

1. **Cyclic Credential Recycling (NIST SP 800-63B Violation)**:
   - *Attack Scenario*: An attacker captures an employee's password during a third-party breach. When the company alerts staff to reset credentials, the employee temporarily sets a throwaway string and immediately changes it back to their original breached password. The adversary retains permanent access.
   - *Mitigation*: Enforce a strict retention window ($N = 10$) preventing users from reusing any of their recent historical passwords across all rotation and recovery vectors.
2. **Rainbow Table & Cross-User Hash Correlation Attacks**:
   - *Attack Scenario*: If historical passwords are saved as unsalted hashes or static MD5/SHA-256 digests, an attacker extracting the database can reconstruct previous passwords through precomputed rainbow tables or identify users who shared identical historical passwords.
   - *Mitigation*: Every historical password entry is stored as a distinct, salted Argon2id hash (`argon2id$v=19$m=65536,t=3,p=4`) generated with high-entropy cryptographic salts (`crypto.randomBytes(16)`).
3. **Automated Password Testing & Account Takeover (ATO)**:
   - *Attack Scenario*: Compromised automated sessions attempt to brute-force candidate passwords against a compromised account to determine which historical passwords the system rejects, probing rotation patterns.
   - *Mitigation*: Emit high-fidelity OpenTelemetry audit events and telemetry hooks consumed by **Endpoint Detection & Response (EDR)** and **Security Information and Event Management (SIEM)** pipelines to trigger step-up challenges or account lockouts.

---

## 📐 2. Architecture & Standards Compliance

### 2.1 Core Invariants

1. **Fixed FIFO Retention Window ($N = 10$)**:
   - The platform strictly enforces retention of the last 10 historical Argon2id password hashes per user (`AUTH_CONSTANTS.SECURITY_CONFIG.PASSWORD_HISTORY_LIMIT = 10`).
2. **Current & Historical Dual Rejection**:
   - Candidate passwords submitted during interactive rotation (`/api/v1/auth/change-password`) or token recovery (`/api/v1/auth/reset-password`) are evaluated against:
     - The user's active current `password_hash`.
     - The top 10 historical records in `auth_password_history`.
   - Matching any entry halts execution with `HTTP 400 Bad Request` and canonical code `PASSWORD_RECENTLY_USED`.
3. **Automatic FIFO Eviction**:
   - Persisting a new password history record triggers an immediate atomic prune query (`PRUNE_OLD_ENTRIES`) in PostgreSQL that purges entries outside the 10 most recent records for that `user_id`, ensuring strictly bounded table growth.
4. **Generation 0 Immutability**:
   - Initial registration (`signUp`) and administrative provisioning (`createUser`, `inviteUser`) persist the genesis password hash into `auth_password_history` immediately upon account creation. Users cannot immediately cycle back to their initial provisioning secret.
5. **Zero Inline Comments & Deeply Immutable DTOs**:
   - Domain logic complies strictly with platform standards: zero inline comments, private-by-default class fields, constructor dependency injection, and complete OpenTelemetry span propagation.

---

## 🔌 3. Hexagonal Architecture & Port Topology

### 3.1 Service & Adapter Boundary Topology

```mermaid
graph TD
    subgraph IngressDrivingPorts ["Driving Ingress (REST Router & Controllers)"]
        H1["POST /api/v1/auth/change-password<br/>(Authenticated Password Rotation)"]
        H2["POST /api/v1/auth/reset-password<br/>(Cryptographic Recovery Token Reset)"]
        H3["POST /api/v1/auth/sign-up<br/>(Initial Genesis Password Registration)"]
    end

    subgraph HexagonalCore ["Hexagonal Domain Core (src/features/auth/ & src/shared/)"]
        direction TB
        PWD["PasswordDomainService<br/>(Evaluates History Window, Prunes Hashes)"]
        AUTH["UserAuthDomainService<br/>(Registers Gen 0 Hashes)"]
        ARGON["argon2.util.ts<br/>(RFC 9106 Memory-Hard Verifier)"]
    end

    subgraph DrivenPorts ["Driven Infrastructure Ports & Adapters (src/infra/)"]
        direction TB
        PORT["AuthRepositoryPort<br/>(recordPasswordHistory, getRecentPasswordHashes)"]
        REAL["RealPostgresAuthAdapter<br/>(AlloyDB / PostgreSQL Cluster)"]
        MOCK["AlloyDBOmniAuthAdapter<br/>(In-Memory & Edge Development Database)"]
        SIEM["OpenTelemetry Tracer & Audit Logger<br/>(EDR / SIEM Detection Stream)"]
    end

    IngressDrivingPorts --> PWD
    IngressDrivingPorts --> AUTH
    PWD --> ARGON
    PWD --> PORT
    AUTH --> PORT
    PORT --> REAL
    PORT --> MOCK
    PWD -.-> SIEM
```

### 3.2 Hexagonal Class & Interface Contract Topology

```mermaid
classDiagram
    class PasswordDomainService {
        -AuthRepositoryPort repo
        -NotificationDomainService notificationService
        -BreachedPasswordDetectorPort breachedPasswordDetector
        +forgotPassword(input: ForgotPasswordInput) Promise~resetToken~
        +resetPassword(input: ResetPasswordInput) Promise~void~
        +changePassword(userId: string, input: ChangePasswordInput) Promise~void~
    }

    class AuthRepositoryPort {
        <<interface>>
        +recordPasswordHistory(userId: string, passwordHash: string, createdAtMs: number) Promise~void~
        +getRecentPasswordHashes(userId: string, limit: number) Promise~string[]~
        +findUserById(userId: string) Promise~AuthUserRecord | null~
        +updateUserPassword(userId: string, newPasswordHash: string) Promise~void~
    }

    class RealPostgresAuthAdapter {
        -Pool pool
        +recordPasswordHistory(userId: string, passwordHash: string, createdAtMs: number) Promise~void~
        +getRecentPasswordHashes(userId: string, limit: number) Promise~string[]~
    }

    class AlloyDBOmniAuthAdapter {
        -Map mockPasswordHistory
        +recordPasswordHistory(userId: string, passwordHash: string, createdAtMs: number) Promise~void~
        +getRecentPasswordHashes(userId: string, limit: number) Promise~string[]~
    }

    PasswordDomainService --> AuthRepositoryPort : Constructor Injected
    RealPostgresAuthAdapter ..|> AuthRepositoryPort : Implements
    AlloyDBOmniAuthAdapter ..|> AuthRepositoryPort : Implements
```

---

## 🔁 4. Sequence Workflows & Execution Pipelines

### 4.1 Authenticated Password Change Workflow

```mermaid
sequenceDiagram
    autonumber
    actor User as Client / User
    participant Router as AuthRestV1Router
    participant Handler as password.handler.ts
    participant Service as PasswordDomainService
    participant Argon as argon2.util.ts
    participant DB as AlloyDB (PostgreSQL)
    participant SIEM as EDR / SIEM Alert Pipeline

    User->>Router: POST /api/v1/auth/change-password { current_password, new_password }
    Router->>Handler: handleChangePassword(service, userId, body)
    Handler->>Service: changePassword(userId, validatedInput)

    Service->>DB: findUserById(userId)
    DB-->>Service: userRecord

    Service->>Argon: verifyPassword(current_password, user.password_hash)
    alt Current Password Invalid
        Argon-->>Service: false
        Service-->>Router: Throw InvalidCredentialsError(401)
        Router-->>User: 401 Unauthorized
    end

    Service->>Argon: verifyPassword(new_password, user.password_hash)
    alt Candidate matches active password
        Argon-->>Service: true
        Service-)SIEM: Emit Event 'PASSWORD_RECYCLE_ATTEMPT' { userId, reason: 'current_match' }
        Service-->>Router: Throw PasswordRecentlyUsedError(400)
        Router-->>User: 400 Bad Request (PASSWORD_RECENTLY_USED)
    end

    Service->>DB: getRecentPasswordHashes(userId, limit = 10)
    DB-->>Service: [hash_0, hash_1, ... hash_9]

    loop Compare Candidate Against 10 Historical Hashes
        Service->>Argon: verifyPassword(new_password, historicalHash)
        alt Candidate matches historical hash
            Argon-->>Service: true
            Service-)SIEM: Emit Event 'PASSWORD_RECYCLE_ATTEMPT' { userId, reason: 'history_match' }
            Service-->>Router: Throw PasswordRecentlyUsedError(400)
            Router-->>User: 400 Bad Request (PASSWORD_RECENTLY_USED)
        end
    end

    Service->>Argon: hashPassword(new_password)
    Argon-->>Service: newHash

    Service->>DB: updateUserPassword(userId, newHash)
    Service->>DB: recordPasswordHistory(userId, newHash)
    Note over DB: INSERT INTO auth_password_history<br/>DELETE oldest where rank > 10

    Service-)SIEM: Emit Event 'PASSWORD_ROTATED_SUCCESS' { userId }
    Service-->>Handler: { success: true }
    Handler-->>Router: StandardApiResponse Envelope
    Router-->>User: 200 OK (Password successfully changed)
```

---

## 🗄️ 5. Database Schema & Entity Relationship Diagram (ERD)

### 5.1 Entity Relationship Diagram (ERD)

```mermaid
erDiagram
    auth_organizations ||--o{ auth_users : "contains (1:N)"
    auth_users ||--o{ auth_password_history : "owns (1:N, max 10)"
    auth_users ||--o{ auth_api_keys : "issues (1:N)"
    auth_users ||--o{ auth_audit_logs : "generates (1:N)"

    auth_organizations {
        varchar(64) id PK
        varchar(255) name UK
        varchar(255) slug UK
        timestamptz created_at
        timestamptz updated_at
        timestamptz deleted_at
    }

    auth_users {
        varchar(64) id PK
        varchar(255) email UK
        varchar(255) password_hash
        varchar(255) name
        varchar(64) org_id FK
        varchar(64) role
        boolean blocked
        timestamptz created_at
        timestamptz updated_at
        timestamptz deleted_at
    }

    auth_password_history {
        varchar(64) id PK
        varchar(64) user_id FK "ON DELETE CASCADE"
        varchar(255) password_hash "Salted Argon2id Digest"
        bigint created_at_ms
        timestamptz created_at
        timestamptz updated_at
        timestamptz deleted_at
    }
```

### 5.2 Migration `0022_create_auth_password_history.sql`

```sql
-- migration:      0022
-- description:    create auth password history table for cyclic reuse prevention
-- author:         Platform Architecture Team
-- date:           2026-10-15
-- depends_on:     0021
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         enforce nist sp 800-63b password history to prevent credential recycling

CREATE TABLE IF NOT EXISTS auth_password_history (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    created_at_ms BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL
);

-- Compound index optimizing ordered retrieval and FIFO pruning
CREATE INDEX IF NOT EXISTS idx_auth_password_history_user_created 
    ON auth_password_history(user_id, created_at DESC) 
    WHERE deleted_at IS NULL;

-- Direct FK lookup index satisfying migration invariant RULE-202
CREATE INDEX IF NOT EXISTS idx_auth_password_history_user_id 
    ON auth_password_history(user_id);
```

### 5.3 Rollback `0022_create_auth_password_history.rollback.sql`

```sql
-- migration:      0022
-- description:    drop auth password history table
-- author:         Platform Architecture Team
-- date:           2026-10-15
-- depends_on:     0021
-- reversible:     YES
-- lock_risk:      LOW
-- rows_affected:  schema only
-- reason:         revert auth password history table

DROP INDEX IF EXISTS idx_auth_password_history_user_id;
DROP INDEX IF EXISTS idx_auth_password_history_user_created;
DROP TABLE IF EXISTS auth_password_history;
```

---

## 🛠️ 6. How To Use It: Operational & Developer Guide

### 6.1 Password Rotation (`POST /api/v1/auth/change-password`)

#### Request (Reusing a Recent Password)

```bash
curl -X POST https://auth.observability.io/api/v1/auth/change-password \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsIn..." \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "CurrentPassword2026!#",
    "new_password": "PreviousPassword2025!#"
  }'
```

#### Response: HTTP 400 Bad Request (Blocked by Policy)

```json
{
  "success": false,
  "statusCode": 400,
  "message": "You cannot reuse any of your last 10 passwords",
  "error": {
    "code": "PASSWORD_RECENTLY_USED",
    "details": "Password matches recent entries in auth_password_history under NIST SP 800-63B policy"
  },
  "meta": {
    "requestId": "req_1729000000000",
    "correlationId": "req_1729000000000",
    "timestamp": "2026-10-15T15:15:00.000Z",
    "executionTimeMs": 14,
    "apiVersion": "1.0.0"
  }
}
```

### 6.2 Password Reset (`POST /api/v1/auth/reset-password`)

#### Request (Resetting to a Retained Historical Secret)

```bash
curl -X POST https://auth.observability.io/api/v1/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "rst_9f83ac08b1a47",
    "new_password": "RecycledPassword2024!#"
  }'
```

#### Response: HTTP 400 Bad Request (Blocked by Policy)

```json
{
  "success": false,
  "statusCode": 400,
  "message": "You cannot reuse any of your last 10 passwords",
  "error": {
    "code": "PASSWORD_RECENTLY_USED"
  }
}
```

---

## 🚨 7. Security Operations, SIEM / EDR Integration, Audit & Telemetry

### 7.1 EDR (Endpoint Detection & Response) & SOC Alerting Rules

When an endpoint management agent (e.g., CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint) or identity protection telemetry detects compromised accounts, tracking credential recycling patterns is a Tier-1 indicator of active unauthorized presence:

| Detection Rule ID | Trigger Condition | Severity | EDR / SIEM Response Action |
|---|---|---|---|
| `SEC-AUTH-REC-001` | $\ge 3$ `PASSWORD_RECENTLY_USED` events within 5 minutes on same `user_id` | **HIGH** | Flag compromised session in EDR; terminate active refresh token family; force step-up biometric challenge. |
| `SEC-AUTH-REC-002` | Successful password rotation followed within 60 seconds by rotation to previous secret | **CRITICAL** | Automated account lockout; invalidate all active bearer JWTs; trip SOC incident for immediate credential stuffing investigation. |
| `SEC-AUTH-REC-003` | Rapid alternation between 2 distinct passwords across reset recovery tokens | **MEDIUM** | Invalidate recovery token; throttle IP subnet with progressive delay. |

### 7.2 OpenTelemetry Spans & Attributes

The password verification pipeline produces structured OpenTelemetry span attributes:

```yaml
span_name: "PasswordDomainService.changePassword"
attributes:
  user.id: "usr_abc123"
  security.password_history.limit: 10
  security.password_history.evaluated_count: 8
  security.password_history.verdict: "REJECTED_RECENT_MATCH" # or "ACCEPTED"
  crypto.algorithm: "argon2id"
  crypto.memory_cost_kib: 65536
  crypto.time_cost: 3
  crypto.parallelism: 4
```

---

## ⚖️ 8. Alternatives Considered & Trade-Off Analysis

| Approach | Advantages | Disadvantages | Verdict |
|---|---|---|---|
| **A. Salted Argon2id Hashes in PostgreSQL (Selected)** | Cryptographically secure; immune to rainbow tables; zero external infrastructure required; foreign key cascade automatically purges history upon user deletion. | Requires $N$ sequential or parallel Argon2id verifications during rotation (~15-40ms). | **Accepted**: Security and compliance benefits strictly outweigh the 30ms latency on infrequent rotation events. |
| **B. Unsalted Hashes / Fast Hashes (SHA-256 / MD5)** | Fast comparison ($< 1$ ms). | Catastrophic vulnerability to offline dictionary attacks and cross-user correlation. | **Rejected**: Violates NIST SP 800-63B and OWASP ASVS storage rules. |
| **C. In-Memory Bloom Filter in Redis** | Instant membership lookup ($O(1)$). | Probabilistic false positives (can reject valid novel passwords); impossible to reliably evict on a FIFO basis without rotating filter structures. | **Rejected**: False positives degrade user trust and violate deterministic validation requirements. |
| **D. 24-Password History Window** | Extends retention across longer timeframe. | Increases Argon2id verification computational overhead proportionally; degrades user experience without adding meaningful entropy security. | **Rejected**: NIST SP 800-63B recommends minimum 10; 10 strikes the optimal security/performance balance. |

---

## 🔄 9. Password Lifecycle & FIFO Eviction State Machine

```mermaid
stateDiagram-v2
    [*] --> Gen0Active: User Provisioned (signUp / inviteUser / createUser)
    Gen0Active --> HistoryPersisted: Genesis Argon2id hash inserted into auth_password_history (N=1)
    
    HistoryPersisted --> RotationCandidate: Candidate password submitted (changePassword / resetPassword)
    
    state RotationCandidate {
        [*] --> CurrentPasswordCheck
        CurrentPasswordCheck --> RejectCurrent: Matches user.password_hash (HTTP 400)
        CurrentPasswordCheck --> EvaluateHistoryParallel: Unique against active hash
        
        EvaluateHistoryParallel --> ParallelArgon2idVerify: Query top 10 historical hashes (auth_password_history)
        ParallelArgon2idVerify --> RejectHistorical: Matches any of top 10 hashes (PASSWORD_RECENTLY_USED)
        ParallelArgon2idVerify --> AcceptNovel: Zero matches across history window
    }
    
    RejectCurrent --> RotationAborted: 400 Bad Request
    RejectHistorical --> RotationAborted: 400 Bad Request (SIEM Event Emitted)
    
    AcceptNovel --> AtomicallyCommitted: UPDATE auth_users SET password_hash = newHash
    AtomicallyCommitted --> InsertHistory: INSERT INTO auth_password_history (user_id, hash, created_at_ms)
    InsertHistory --> PruneOldEntries: DELETE FROM auth_password_history WHERE id NOT IN (top 10 by created_at_ms)
    PruneOldEntries --> RotationActive: Fresh session issued, history window clamped to N=10
    
    RotationAborted --> [*]
    RotationActive --> [*]
```

---

## ⚡ 10. Memory & Performance Guardrails (Parallel Evaluation)

To ensure Argon2id evaluations adhere to [4-performance-and-durability.md](file:///home/btpl-lap-22/live/llm-obs-node-packages/llm-obs-policies/rules/code-quality/coding-standards/4-performance-and-durability.md) and bounded execution:
- **Bounded Worker Pool**: Historical Argon2id verifications execute using `Promise.all` with maximum concurrency bounded to `parallelism = 4`, preventing worker thread pool starvation.
- **Circuit Breaker on History Query**: If database query exceeds $200\text{ ms}$, the service fails closed to prevent unverified password reuse during database degradation.
- **Strict Compliance**: Adheres to [4-functions-and-classes-writing-rule.md](file:///home/btpl-lap-22/live/llm-obs-node-packages/llm-obs-policies/rules/folder-structure/4-functions-and-classes-writing-rule.md) with typed `Result<T, E>` returns and zero inline comments.


## Execution Flow (Call Stack Tree)

```text
createServer(listener: (req: IncomingMessage, res: ServerResponse) => void): Server
└── runWithHttpTracing(req: IncomingMessage, res: ServerResponse, fn: () => Promise<void>): Promise<void>
    └── dispatch(method: string, path: string, body: unknown, headers: Record<string, string>): Promise<RouteDispatchResult>
        ├── matchRoute(method: string, path: string): { rule: RouteRule, params: Record<string, string> } | null
        ├── handler(ctx: RouteContext): Promise<void>
        │   assertPasswordHistory(userId: string, newPasswordPlain: string): Promise<void>
        │   ├── fetchHistoricalPasswordHashes(userId: string, depth: number): Promise<string[]>
        │   ├── verifyPasswordAgainstHistory(hashes: string[], plain: string): Promise<boolean>
        │   └── archivePasswordHash(userId: string, newHash: string): Promise<void>
        ├── createSuccessResponse(data: void, message: string, meta: ResponseMeta, statusCode: number): ApiResponse<void>
        └── end(chunk: string): ServerResponse

// Type Reference:
// ApiResponse<T>      = { success: boolean, statusCode: number, message: string, data: T, meta: ResponseMeta }
// RouteDispatchResult = { statusCode: number, payload: ApiResponse<void>, headers: Record<string, string> }
```

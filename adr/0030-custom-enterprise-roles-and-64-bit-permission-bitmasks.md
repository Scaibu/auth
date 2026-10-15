# ADR 0030: Custom Enterprise Roles and 64-Bit Permission Bitmasks

## Status
Accepted

## Context
Enterprise multi-tenant environments require fine-grained access control that moves beyond rigid fixed roles (`owner`, `admin`, `member`, `viewer`). While Relationship-Based Access Control (ReBAC / Zanzibar, ADR 0023) supports deep object-level graph relationships, high-frequency control plane operations (such as API authorization gates, UI permission checks, and telemetry endpoints) require sub-millisecond evaluation with zero graph traversal overhead.

Relational permission queries requiring joins across `users`, `roles`, `role_permissions`, and `permissions` introduce significant latency ($O(N)$ joins) and database CPU load under high request concurrency.

## Decision
We implement a **Tenant-Scoped Custom Role Engine** backed by a **64-bit Permission Bitmask**:
1. **64-bit Bitmask Architecture**:
   - Each atomic permission action is assigned a distinct bit position ($2^0$ to $2^{62}$) represented as a JavaScript `bigint` and PostgreSQL `NUMERIC(20, 0)` to guarantee safe 64-bit unsigned storage without signed integer overflow.
   - Bitwise evaluation is $O(1)$ in CPU memory: `(effectiveMask & requiredMask) === requiredMask`.
2. **Multi-Role Aggregation**:
   - Users can be assigned multiple roles within an organization.
   - The user's effective permission bitmask is computed as the bitwise OR of all active assigned role bitmasks:
     $$\text{EffectiveMask} = \bigvee_{r \in \text{Roles}} \text{Mask}_r$$
3. **Fail-Closed Verification**:
   - If an evaluation encounters an unknown permission key or empty role set without explicitly granted bits, evaluation immediately denies access.
4. **Distributed Tracing & Zero Inline Comments**:
   - All evaluation and role mutations are instrumented with OpenTelemetry spans (`withSpan`) attaching audit attributes (`auth.role_id`, `auth.permission_bitmask`, `auth.evaluation_granted`).

---

## Detailed Data Tables & Architecture Specifications

### 1. Database Table Specifications & Schema Invariants (Storage Gate)

| Table | Column | Type | Nullable | Default | Constraints & Invariants | Purpose |
|---|---|---|---|---|---|---|
| **`auth_permission_registry`** | `permission_key` | `VARCHAR(64)` | `NO` | - | `PRIMARY KEY`, uppercase canonical key | System-wide unique identifier for permission |
| | `bit_position` | `INT` | `NO` | - | `UNIQUE`, `CHECK (bit_position >= 0 AND bit_position <= 62)` | Exact bit index in 64-bit mask ($0..62$) |
| | `bitmask` | `NUMERIC(20, 0)` | `NO` | - | `UNIQUE`, `CHECK (bitmask > 0)` | Numeric representation of 2^(bit_position) |
| | `category` | `VARCHAR(32)` | `NO` | - | Bounded string (e.g. `ORGANIZATION`, `USER`, `SECURITY`) | Domain categorization for UI grouping |
| | `description` | `VARCHAR(255)` | `NO` | - | Explanatory text | Human-readable explanation of granted capability |
| | `created_at_ms` | `BIGINT` | `NO` | - | Epoch milliseconds | Timestamp of registry insertion |
| **`auth_custom_roles`** | `id` | `VARCHAR(64)` | `NO` | - | `PRIMARY KEY`, internal UUIDv7 (`crole_...`) | Surrogate primary key |
| | `public_id` | `VARCHAR(64)` | `NO` | - | `UNIQUE`, external opaque ID (`pub_crole_...`) | External API and audit reference |
| | `org_id` | `VARCHAR(64)` | `NO` | - | `FK -> auth_organizations(id) ON DELETE CASCADE` | Tenant ownership & partition key |
| | `name` | `VARCHAR(64)` | `NO` | - | `CHECK (name = btrim(name) AND name <> '')` | Trimmed role name (e.g., `SRE Lead`) |
| | `description` | `VARCHAR(255)` | `NO` | `''` | Role summary | Explanation of role purpose |
| | `permission_mask` | `NUMERIC(20, 0)` | `NO` | `0` | `CHECK (permission_mask >= 0 AND <= 9223372036854775807)` | Composite bitmask of granted permissions |
| | `is_system_role` | `BOOLEAN` | `NO` | `FALSE` | Immutable system role flag | Protects default roles from deletion/mutation |
| | `version` | `BIGINT` | `NO` | `1` | `CHECK (version >= 1)` | Optimistic concurrency version counter |
| | `created_by` | `VARCHAR(64)` | `YES` | `NULL` | User ID of creator | Audit tracking of role creation |
| | `created_at_ms` | `BIGINT` | `NO` | - | Epoch milliseconds | Audit timestamp |
| | `updated_at_ms` | `BIGINT` | `NO` | - | Epoch milliseconds | Audit timestamp |
| | `deleted_at` | `TIMESTAMPTZ` | `YES` | `NULL` | Soft delete marker | 30-day retention and soft-deletion marker |
| | **Table Constraints** | - | - | - | `UNIQUE (public_id)`<br/>`UNIQUE (org_id, id)`<br/>`UNIQUE (org_id, name)` | Enforces tenant-unique names and composite FKs |
| **`auth_user_custom_roles`** | `id` | `VARCHAR(64)` | `NO` | - | `PRIMARY KEY`, internal UUIDv7 (`ucrole_...`) | Surrogate primary key |
| | `public_id` | `VARCHAR(64)` | `NO` | - | `UNIQUE`, external ID (`pub_ucrole_...`) | External API reference |
| | `org_id` | `VARCHAR(64)` | `NO` | - | `FK -> auth_organizations(id) ON DELETE CASCADE` | Tenant isolation partition key |
| | `user_id` | `VARCHAR(64)` | `NO` | - | `FK -> auth_users(id) ON DELETE CASCADE` | Assigned user |
| | `role_id` | `VARCHAR(64)` | `NO` | - | `FK (org_id, role_id) -> auth_custom_roles(org_id, id)` | Tenant-safe composite foreign key |
| | `version` | `BIGINT` | `NO` | `1` | `CHECK (version >= 1)` | Optimistic locking counter |
| | `assigned_by` | `VARCHAR(64)` | `YES` | `NULL` | User ID of assigner | Audit tracking |
| | `assigned_at_ms` | `BIGINT` | `NO` | - | Epoch milliseconds | Timestamp of assignment |
| | `deleted_at` | `TIMESTAMPTZ` | `YES` | `NULL` | Soft delete marker | Revocation timestamp |
| | **Table Constraints** | - | - | - | `UNIQUE (public_id)`<br/>`UNIQUE (org_id, user_id, role_id)` | Prevents duplicate user-role bindings |
| **`auth_role_audit_logs`** | `id` | `VARCHAR(64)` | `NO` | - | `PRIMARY KEY`, UUIDv7 (`raudit_...`) | Immutable audit event identifier |
| | `org_id` | `VARCHAR(64)` | `NO` | - | `FK -> auth_organizations(id) ON DELETE CASCADE` | Tenant scope |
| | `actor_user_id` | `VARCHAR(64)` | `NO` | - | User ID | Actor initiating the role mutation |
| | `action` | `VARCHAR(32)` | `NO` | - | `CHECK (action IN ('ROLE_CREATED', 'ROLE_UPDATED', ...))` | Audited role lifecycle event |
| | `target_role_id` | `VARCHAR(64)` | `NO` | - | Role ID | Affected role |
| | `target_user_id` | `VARCHAR(64)` | `YES` | `NULL` | User ID | Affected user (for assignments) |
| | `previous_mask` | `NUMERIC(20, 0)` | `YES` | `NULL` | Prior permission bitmask | Delta analysis for compliance |
| | `new_mask` | `NUMERIC(20, 0)` | `YES` | `NULL` | Updated permission bitmask | Delta analysis for compliance |
| | `reason` | `VARCHAR(255)` | `NO` | `''` | Justification note | Compliance audit note |
| | `created_at_ms` | `BIGINT` | `NO` | - | Epoch milliseconds | Tamper-proof audit timestamp |

---

### 2. Entity-Relationship Diagram

```mermaid
erDiagram
    AUTH_ORGANIZATIONS ||--o{ AUTH_CUSTOM_ROLES : "scopes (1:N)"
    AUTH_ORGANIZATIONS ||--o{ AUTH_USERS : "contains (1:N)"
    AUTH_ORGANIZATIONS ||--o{ AUTH_USER_CUSTOM_ROLES : "tenant_isolates (1:N)"
    AUTH_ORGANIZATIONS ||--o{ AUTH_ROLE_AUDIT_LOGS : "audits (1:N)"
    AUTH_USERS ||--o{ AUTH_USER_CUSTOM_ROLES : "assigned_to (1:N)"
    AUTH_CUSTOM_ROLES ||--o{ AUTH_USER_CUSTOM_ROLES : "binds_composite (1:N)"
    AUTH_PERMISSION_REGISTRY ||--o{ AUTH_CUSTOM_ROLES : "composed_via_bits (N:M)"

    AUTH_PERMISSION_REGISTRY {
        varchar(64) permission_key PK "Canonical key e.g. USERS_READ"
        int bit_position UK "0 to 62 strictly sequential"
        numeric(20_0) bitmask UK "Precomputed bitmask (1n << bit_position)"
        varchar(32) category "ORGANIZATION | USER | API_KEY | ..."
        varchar(255) description "Human readable description"
        bigint created_at_ms "Registration epoch timestamp"
    }

    AUTH_ORGANIZATIONS {
        varchar(64) id PK "org_uuidv7"
        varchar(255) name UK
        varchar(255) slug UK
        timestamp created_at
    }

    AUTH_USERS {
        varchar(64) id PK "usr_uuidv7"
        varchar(255) email UK
        varchar(64) org_id FK "REFERENCES auth_organizations(id)"
        varchar(64) role "Legacy fallback role string"
    }

    AUTH_CUSTOM_ROLES {
        varchar(64) id PK "crole_uuidv7"
        varchar(64) public_id UK "pub_crole_uuidv7"
        varchar(64) org_id FK "REFERENCES auth_organizations(id)"
        varchar(64) name "UNIQUE(org_id, name) WHERE deleted_at IS NULL"
        varchar(255) description
        numeric(20_0) permission_mask "64-bit unsigned BigInt bitmask"
        boolean is_system_role "Immutable system protected role flag"
        bigint version "Optimistic locking version counter"
        varchar(64) created_by "Actor user ID"
        bigint created_at_ms
        bigint updated_at_ms
        timestamp deleted_at "Soft delete marker"
    }

    AUTH_USER_CUSTOM_ROLES {
        varchar(64) id PK "ucrole_uuidv7"
        varchar(64) public_id UK "pub_ucrole_uuidv7"
        varchar(64) org_id FK "Tenant isolation scope"
        varchar(64) user_id FK "REFERENCES auth_users(id)"
        varchar(64) role_id FK "REFERENCES auth_custom_roles(org_id, id)"
        bigint version "Row version counter"
        varchar(64) assigned_by "Granting actor user ID"
        bigint assigned_at_ms
        timestamp deleted_at "Soft delete marker"
    }

    AUTH_ROLE_AUDIT_LOGS {
        varchar(64) id PK "raudit_uuidv7"
        varchar(64) org_id FK "REFERENCES auth_organizations(id)"
        varchar(64) actor_user_id "Actor user ID"
        varchar(32) action "ROLE_CREATED | ROLE_UPDATED | ROLE_DELETED | ROLE_ASSIGNED | ROLE_REVOKED"
        varchar(64) target_role_id "Target role ID"
        varchar(64) target_user_id "Nullable: target user ID for assignments"
        numeric(20_0) previous_mask "Nullable: prior bitmask for diffs"
        numeric(20_0) new_mask "Nullable: updated bitmask for diffs"
        varchar(255) reason "Audit justification"
        bigint created_at_ms "Append-only epoch timestamp"
    }
```

---

### 3. Canonical 64-Bit Permission Bit Allocation Layout

```
 Bit Index:
  63 62 61 ... 37 36 35 34 33 32 | 31 30 29 ... 25 24 | 23 22 21 ... 17 16 | 15 14 13 ... 9  8  | 7  6  5 ... 2  1  0
 ┌──┬──┬──┬───┬──┬──┬──┬──┬──┬──┬┼──┬──┬──┬───┬──┬──┬┼──┬──┬──┬───┬──┬──┬┼──┬──┬──┬───┬──┬──┬┼──┬──┬──┬───┬──┬──┐
 │0 │R │R │...│R │P │S │S │P │A ││R │R │R │...│W │R ││R │R │R │...│C │R ││R │R │R │...│I │R ││R │R │R │...│D │U │R │
 └──┴──┴──┴───┴──┴──┴──┴──┴──┴──┴┴──┴──┴──┴───┴──┴──┴┴──┴──┴──┴───┴──┴──┴┴──┴──┴──┴───┴──┴──┴┴──┴──┴──┴───┴──┴──┘
  ▲               ▲  ▲  ▲  ▲  ▲               ▲  ▲               ▲  ▲               ▲  ▲               ▲  ▲  ▲
  │               │  │  │  │  │               │  │               │  │               │  │               │  │  └─ ORG_READ (1)
  │               │  │  │  │  │               │  │               │  │               │  │               │  └─── ORG_UPDATE (2)
  │               │  │  │  │  │               │  │               │  │               │  │               └────── ORG_DELETE (4)
  │               │  │  │  │  │               │  │               │  │               │  └────────────────────── USERS_READ (256)
  │               │  │  │  │  │               │  │               │  │               └───────────────────────── USERS_INVITE (512)
  │               │  │  │  │  │               │  │               │  └───────────────────────────────────────── API_KEYS_READ (65536)
  │               │  │  │  │  │               │  │               └──────────────────────────────────────────── API_KEYS_CREATE (131072)
  │               │  │  │  │  │               │  └──────────────────────────────────────────────────────────── TELEMETRY_READ (16777216)
  │               │  │  │  │  │               └─────────────────────────────────────────────────────────────── TELEMETRY_WRITE (33554432)
  │               │  │  │  │  └─────────────────────────────────────────────────────────────────────────────── AUDIT_LOGS_READ (4294967296)
  │               │  │  │  └────────────────────────────────────────────────────────────────────────────────── POLICIES_MANAGE (8589934592)
  │               │  │  └───────────────────────────────────────────────────────────────────────────────────── SAML_MANAGE (17179869184)
  │               │  └──────────────────────────────────────────────────────────────────────────────────────── SCIM_MANAGE (34359738368)
  │               └─────────────────────────────────────────────────────────────────────────────────────────── PASSKEYS_MANAGE (68719476736)
  └─ Bit 63: Reserved for Overflow Safety (Non-negative signed BigInt boundary)
```

---

### 4. Custom Enterprise Role Lifecycle & Concurrency State Machine

```mermaid
stateDiagram-v2
    [*] --> ActiveDraft: POST /api/v1/auth/roles (version=1, is_system_role=false)
    ActiveDraft --> BitmaskUpdated: PUT /api/v1/auth/roles/:id (version = V + 1)
    
    state BitmaskUpdated {
        [*] --> VerifyOptimisticLock
        VerifyOptimisticLock --> CommitUpdate: WHERE version = expectedVersion
        VerifyOptimisticLock --> ConcurrencyConflict: version != expectedVersion
        CommitUpdate --> AuditLogged: INSERT INTO auth_role_audit_logs
        ConcurrencyConflict --> AbortTransaction: 409 Conflict returned
    }

    BitmaskUpdated --> ActiveDraft: Transaction committed with updated mask
    AbortTransaction --> ActiveDraft: Client re-fetches latest role state

    ActiveDraft --> AssignedToUser: POST /api/v1/auth/users/:id/roles
    AssignedToUser --> RevokedFromUser: DELETE /api/v1/auth/users/:id/roles/:roleId (deleted_at = NOW())
    RevokedFromUser --> ActiveDraft: Role unassigned from user

    ActiveDraft --> SystemLocked: Role seeded/flagged (is_system_role=true)
    SystemLocked --> ModificationRejected: Mutation attempted on system role
    ModificationRejected --> SystemLocked: 403 Forbidden ("System roles are immutable")

    ActiveDraft --> SoftDeleted: DELETE /api/v1/auth/roles/:id (deleted_at = NOW())
    SoftDeleted --> [*]: Soft-deleted role excluded from runtime bitmask queries
```

---

### 5. Bitwise Evaluation Runtime Flowchart

```mermaid
flowchart TD
    Req(["Request: Evaluate User Permissions"]) --> CacheCheck{"Cache Hit in Redis L1?"}
    CacheCheck -- "Yes (TTL &lt; 60s)" --> CachedMask["Load Cached Aggregated Bitmask"]
    CacheCheck -- "No" --> FetchDB["Query Active User Roles (auth_user_custom_roles + auth_custom_roles)"]
    
    FetchDB --> RolesFound{"Any active roles returned?"}
    RolesFound -- No --> LegacyCheck{"Legacy role fallback?"}
    LegacyCheck -- "'admin' or 'owner'" --> FullAccess["Grant All System Bits: (1n &lt;&lt; 37n) - 1n"]
    LegacyCheck -- "Other or None" --> DenyZero["EffectiveMask = 0n"]
    
    RolesFound -- Yes --> Aggregate["Aggregate EffectiveMask = Bitwise OR of all Role Masks"]
    Aggregate --> SaveCache["Write EffectiveMask to Redis L1 (TTL 60s)"]
    SaveCache --> CompareBits
    CachedMask --> CompareBits
    FullAccess --> CompareBits
    DenyZero --> CompareBits
    
    CompareBits["Evaluate: (EffectiveMask &amp; RequiredMask) == RequiredMask"]
    CompareBits -- "Match" --> Allow(["Result: GRANTED = TRUE"])
    CompareBits -- "Mismatch" --> Diff["MissingBits = RequiredMask &amp; (~EffectiveMask)"]
    Diff --> Deny(["Result: GRANTED = FALSE, Return MissingBits Hex/Decimal"])
```

---

### 6. Detailed End-to-End Runtime Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Client as API Consumer / Frontend
    participant Gateway as API Gateway / Router
    participant Service as CustomRoleService
    participant Tracing as OpenTelemetry Tracer
    participant Cache as Redis L1 Cache
    participant DB as AlloyDB Omni (PostgreSQL 16)
    participant Audit as Append-Only Audit Log

    Note over Client, DB: Phase 1: Custom Role Creation & Audit
    Client->>Gateway: POST /api/v1/auth/roles { name, description, permission_mask }
    Gateway->>Service: createCustomRole(orgId, params, actorId)
    Service->>Tracing: withSpan("CustomRoleService.createCustomRole")
    Service->>DB: SELECT id FROM auth_custom_roles WHERE org_id = $1 AND name = $2 AND deleted_at IS NULL
    DB-->>Service: NULL (Name uniqueness satisfied)
    Service->>DB: BEGIN Transaction
    Service->>DB: INSERT INTO auth_custom_roles (id, public_id, org_id, name, mask, version=1)
    DB-->>Service: Row inserted (crole_uuidv7)
    Service->>Audit: INSERT INTO auth_role_audit_logs (ROLE_CREATED, new_mask, actor_user_id)
    Audit-->>Service: Audit log row committed
    Service->>DB: COMMIT Transaction
    Service-->>Gateway: Return CustomRoleRecord
    Gateway-->>Client: 201 Created (id, public_id, permission_mask, version=1)

    Note over Client, DB: Phase 2: Role Assignment with Atomic Isolation
    Client->>Gateway: POST /api/v1/auth/users/{userId}/roles { role_ids }
    Gateway->>Service: assignUserCustomRoles(orgId, userId, roleIds, actorId)
    Service->>DB: BEGIN Transaction
    Service->>DB: UPDATE auth_user_custom_roles SET deleted_at = NOW() WHERE org_id = $1 AND user_id = $2
    loop For each role_id
        Service->>DB: INSERT INTO auth_user_custom_roles (id, public_id, org_id, user_id, role_id, version=1)
        Service->>Audit: INSERT INTO auth_role_audit_logs (ROLE_ASSIGNED, target_user_id)
    end
    Service->>DB: COMMIT Transaction
    Service->>Cache: DEL auth:roles:effective:{orgId}:{userId} (Invalidate cache)
    Service-->>Gateway: Success (200 OK)
    Gateway-->>Client: 200 OK

    Note over Client, DB: Phase 3: Sub-Millisecond Bitmask Evaluation
    Client->>Gateway: POST /api/v1/auth/permissions/evaluate { org_id, user_id, required_permissions }
    Gateway->>Service: evaluateUserPermissions(orgId, userId, requiredPermissions)
    Service->>Cache: GET auth:roles:effective:{orgId}:{userId}
    alt Cache Miss
        Service->>DB: SELECT r.permission_mask FROM auth_custom_roles r JOIN auth_user_custom_roles u ON ...
        DB-->>Service: [maskA, maskB]
        Note over Service: Aggregate EffectiveMask = maskA | maskB
        Service->>Cache: SET auth:roles:effective:{orgId}:{userId} EffectiveMask EX 60
    else Cache Hit
        Cache-->>Service: Cached EffectiveMask
    end
    Note over Service: Compute RequiredMask = perm1 | perm2<br/>isGranted = (Effective &amp; Required) == Required
    alt Permissions Satisfied
        Service-->>Gateway: { granted: true, effective_mask, missing_bits: "0" }
    else Missing Permissions
        Service-->>Gateway: { granted: false, effective_mask, missing_bits }
    end
    Gateway-->>Client: 200 OK
```

---

## 🔄 7. Multi-Tenant Role Composition & Bitwise Aggregation Tree

```mermaid
flowchart LR
    subgraph OrganizationBoundary ["Tenant Isolation Boundary (org_id = $1)"]
        direction TB
        CR1["Custom Role: Telemetry Analyst<br/>Mask: 0x0000000003000000n<br/>(TELEMETRY_READ | TELEMETRY_WRITE)"]
        CR2["Custom Role: User Manager<br/>Mask: 0x0000000000000300n<br/>(USERS_READ | USERS_INVITE)"]
        CR3["Custom Role: Audit Inspector<br/>Mask: 0x0000000100000000n<br/>(AUDIT_LOGS_READ)"]
    end

    User(["Assigned User: usr_enterprise99"]) --> CR1
    User --> CR2
    User --> CR3

    CR1 --> BitwiseEngine["Bitwise Aggregator (OR Operator)<br/>EffectiveMask = CR1 | CR2 | CR3"]
    CR2 --> BitwiseEngine
    CR3 --> BitwiseEngine

    BitwiseEngine --> Evaluator{"Permission Check:<br/>(Effective &amp; Required) == Required"}
    Evaluator -- "Sub-Microsecond Bitwise AND" --> FastDecision(["Zero-IO Decision: GRANTED / DENIED"])
```

---

## 🛡 8. Architectural & Clean Code Invariants

- **Functions & Classes**: Adheres strictly to [4-functions-and-classes-writing-rule.md](file:///home/btpl-lap-22/live/llm-obs-node-packages/llm-obs-policies/rules/folder-structure/4-functions-and-classes-writing-rule.md) (stateless domain service, zero comments in code, constructor dependency injection, explicit `try/catch/finally` span ownership).
- **Shared Code Discipline**: Conforms to [3.shared.code.writing.rule.md](file:///home/btpl-lap-22/live/llm-obs-node-packages/llm-obs-policies/rules/folder-structure/3.shared.code.writing.rule.md) with pure bitwise operations in `src/shared/utils/` and centralized error hierarchy.
- **API Response Envelopes**: Complies with [2-apis.writing.rule.md](file:///home/btpl-lap-22/live/llm-obs-node-packages/llm-obs-policies/rules/folder-structure/2-apis.writing.rule.md) ensuring all role management endpoints wrap payloads in standardized response envelopes.

---

## Consequences
- **Positive**:
  - Full adherence to [05-db-writing-rules.md](file:///home/btpl-lap-22/live/llm-obs-node-packages/llm-obs-policies/rules/folder-structure/05-db-writing-rules.md) with surrogate `id`, external `public_id`, composite `(org_id, id)` FKs, check constraints, version columns, and audit logging.
  - $O(1)$ authorization evaluation in critical telemetry and control planes.
- **Negative**:
  - Maximum 63 bits per permission set (extensible with multi-word arrays when needed).


# 0016: Automated 30-Day Cascade Soft-Delete Purge Cron Worker (GDPR Article 17)

- **Status**: Accepted
- **Date**: 2026-10-14
- **Authors**: Platform Architecture & Core Auth Team
- **RFC / Standards**: GDPR Article 17 ("Right to be Forgotten"), ISO/IEC 27001 A.8.10 (Information Deletion), NIST SP 800-88 Rev. 1 (Media Sanitization)
- **Deciders**: Lead Platform Architect, Lead Infrastructure Engineer, Security Officer

---

## 1. Context & Problem Statement

The `@observability/auth` platform implements a soft-deletion pattern (`deleted_at = CURRENT_TIMESTAMP`) across its primary entities (`auth_organizations`, `auth_users`, `auth_api_keys`, `auth_audit_logs`, `auth_password_resets`, and `auth_token_denylist`). This soft-delete architecture is critical for:
1. Preventing accidental, irreversible data loss.
2. Preserving referential integrity and audit trail during in-flight operations.
3. Allowing administrative recovery within a 30-day grace period.

However, soft deletion alone creates a serious legal and operational compliance vulnerability:
- **GDPR Article 17 Violation**: Organizations are legally required to permanently purge personal data without undue delay once the retention purpose has expired. Indefinite soft-deletion fails regulatory audits.
- **OLTP Index & Storage Bloat**: Soft-deleted tombstones accumulate inside PostgreSQL/AlloyDB indexes (`B-tree`), degrading query planner index scans and caching efficiency.
- **Missing Automation**: While SQL purge queries (`FLOW_RETENTION_PURGE`) exist in the codebase, they require manual administrative execution and are not autonomously scheduled or executed with distributed concurrency protection.

---

## 2. Decision Drivers

1. **Autonomous Scheduled Execution**: Background purge execution must run deterministically on a configurable cron interval (defaulting to 02:00 UTC daily) without requiring human intervention.
2. **Distributed Leader Election & Mutex Locking**: Multi-instance cluster replicas must never execute the purge worker simultaneously. A distributed mutex lease (via Redis or database lock) must guarantee single-leader execution.
3. **Batch-Chunked Cascade Execution**: Large volumes of expired records must be purged in bounded batches (e.g., 500 rows per transaction) to prevent table locks and IO spikes on live customer OLTP traffic.
4. **Audit Trail & Observability**: Every execution run must emit OpenTelemetry spans (`PurgeRetentionCronWorker.executePurge`), structured metrics (rows purged per table), and immutable audit logs.
5. **Fail-Safe Manual Administrative Override**: An authenticated administrative endpoint (`POST /api/v1/auth/admin/purge-expired`) protected by RBAC and RFC 9470 Step-Up Authentication must allow on-demand execution.

---

## 3. High-Level Architecture (HLD)

The following sequence illustrates the autonomous cron execution lifecycle with distributed mutex acquisition:

```mermaid
sequenceDiagram
    autonumber
    participant Scheduler as Cron Engine / Timer
    participant Worker as PurgeRetentionCronWorker
    participant LockStore as Distributed Lock (Redis / DB)
    participant DB as Postgres / AlloyDB Cluster
    participant OTEL as OpenTelemetry Collector

    Scheduler->>Worker: Trigger Scheduled Purge Job (Daily 02:00 UTC)
    Worker->>OTEL: Start Active Span ("PurgeRetentionCronWorker.executePurge")
    Worker->>LockStore: Acquire Lock ("auth:lock:retention_purge", TTL=300s)
    
    alt Lock Acquisition Failed (Another instance is running)
        LockStore-->>Worker: Lock Busy (false)
        Worker->>OTEL: Set Span Attribute ("purge.status", "skipped_lock_busy")
        Worker->>OTEL: End Span (OK)
    else Lock Acquired (Leader Elected)
        LockStore-->>Worker: Lock Granted (true)
        Worker->>DB: BEGIN Transaction
        Worker->>DB: 1. DELETE FROM auth_organizations WHERE deleted_at < NOW() - 30 days
        Worker->>DB: 2. DELETE FROM auth_users WHERE deleted_at < NOW() - 30 days
        Worker->>DB: 3. DELETE FROM auth_api_keys WHERE deleted_at < NOW() - 30 days
        Worker->>DB: 4. DELETE FROM auth_audit_logs WHERE deleted_at < NOW() - 30 days
        Worker->>DB: 5. DELETE FROM auth_password_resets WHERE deleted_at < NOW() - 30 days
        Worker->>DB: 6. DELETE FROM auth_token_denylist WHERE expires_at_ms < NOW()
        Worker->>DB: COMMIT Transaction
        DB-->>Worker: Purged Counts per Entity
        Worker->>LockStore: Release Lock ("auth:lock:retention_purge")
        Worker->>OTEL: Record Metrics & Set Span Status (OK)
        Worker->>OTEL: End Span
    end
```

---

## 4. Entity Lifecycle & Purge State Machine

```mermaid
stateDiagram-v2
    [*] --> Active: User / Org Created
    Active --> SoftDeleted: User Requests Deletion / Admin Removes Org
    note right of SoftDeleted
      deleted_at = CURRENT_TIMESTAMP
      Immediate access revoked
      In-flight sessions terminated
    end note
    
    SoftDeleted --> Active: Admin Recovery (Within 30-Day Window)
    SoftDeleted --> ExpiredForPurge: Retention Window Elapsed (Age > 30 Days)
    
    ExpiredForPurge --> PhysicallyPurged: PurgeRetentionCronWorker Run
    note right of PhysicallyPurged
      Physical hard deletion from DB
      WAL records trimmed via VACUUM
      GDPR Article 17 Compliant
    end note
    
    PhysicallyPurged --> [*]
```

---

## 5. Entity Relationship & Cascade Dependency Diagram (ERD)

```mermaid
erDiagram
    auth_organizations ||--o{ auth_users : "cascades soft-delete & purge"
    auth_organizations ||--o{ auth_api_keys : "cascades soft-delete & purge"
    auth_organizations ||--o{ auth_audit_logs : "cascades soft-delete & purge"
    auth_users ||--o{ auth_password_resets : "cascades soft-delete & purge"
    auth_users ||--o{ auth_token_denylist : "token revocation"

    auth_organizations {
        string id PK
        string name
        string slug
        timestamp deleted_at "Indexed for purge"
    }

    auth_users {
        string id PK
        string org_id FK
        string email
        timestamp deleted_at "Indexed for purge"
    }

    auth_api_keys {
        string key_id PK
        string org_id FK
        string user_id FK
        timestamp deleted_at "Indexed for purge"
    }

    auth_audit_logs {
        string id PK
        string org_id FK
        string user_id FK
        timestamp deleted_at "Indexed for purge"
    }

    auth_password_resets {
        string token_hash PK
        string user_id FK
        timestamp deleted_at "Indexed for purge"
    }

    auth_token_denylist {
        string jti PK
        bigint expires_at_ms "Indexed for purge"
    }
```

---

## 6. Implementation Specifications

### 6.1 Database Migration
Add composite/partial indexes to optimize the cutoff purge scan:
- `CREATE INDEX IF NOT EXISTS idx_auth_orgs_deleted_at ON auth_organizations (deleted_at) WHERE deleted_at IS NOT NULL;`
- `CREATE INDEX IF NOT EXISTS idx_auth_users_deleted_at ON auth_users (deleted_at) WHERE deleted_at IS NOT NULL;`
- `CREATE INDEX IF NOT EXISTS idx_auth_api_keys_deleted_at ON auth_api_keys (deleted_at) WHERE deleted_at IS NOT NULL;`
- `CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_deleted_at ON auth_audit_logs (deleted_at) WHERE deleted_at IS NOT NULL;`
- `CREATE INDEX IF NOT EXISTS idx_auth_resets_deleted_at ON auth_password_resets (deleted_at) WHERE deleted_at IS NOT NULL;`

### 6.2 Worker Component (`PurgeRetentionCronWorker`)
- Located in `src/infra/workers/purge-retention-cron.worker.ts`.
- Manages unref timers to avoid keeping Node.js event loops alive during test teardown.
- Implements `executePurge(ctx?: TraceContext): Promise<PurgeSummary>`.

### 6.3 Admin REST API
- `POST /api/v1/auth/admin/purge-expired`
- Headers:
  - `Authorization: Bearer <ADMIN_JWT>`
  - `X-Reauth-Token: <STEP_UP_TOKEN>` (Protected high-value action RFC 9470)
- Response Envelope:
  ```json
  {
    "status": "success",
    "message": "Retention purge completed successfully",
    "data": {
      "purged_records": 42,
      "cutoff_timestamp": "2026-09-14T02:00:00.000Z",
      "duration_ms": 14.5
    }
  }
  ```

---

## 7. Consequences & Trade-Offs

### Positive
- **Guaranteed Regulatory Compliance**: Meets strict 30-day GDPR Article 17 and ISO/IEC 27001 data destruction windows.
- **Database Health**: Automatically prevents bloat across index tables and dead tuples.
- **Zero Cluster Contention**: Distributed locking prevents competing database deletions.

### Negative / Mitigations
- **Non-Recoverable Hard Deletion**: Once purged, records cannot be restored.
  - *Mitigation*: The 30-day grace period is strictly enforced (`deleted_at < NOW() - INTERVAL '30 days'`).

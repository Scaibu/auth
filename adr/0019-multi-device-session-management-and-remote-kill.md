# ADR 0019: Multi-Device Session Management & Remote Kill (OWASP ASVS 3.3)

- **Status**: Accepted
- **Date**: 2026-10-14
- **Authors**: Platform Architecture & Core Auth Team
- **RFC / Standards**: OWASP ASVS 4.0 §3.3 ("Session Logout and Expiration Requirements"), NIST SP 800-63B §7.1 ("Session Management"), RFC 6749 §10.4 ("Refresh Token Rotation")
- **Deciders**: Lead Platform Architect, Lead Security Engineer, Compliance Officer

---

## 📑 Table of Contents

1. [Context & Problem Statement](#1-context--problem-statement)
2. [Decision Drivers](#2-decision-drivers)
3. [High-Level Design (HLD) & Architectural Topology](#3-high-level-design-hld--architectural-topology)
4. [Low-Level Design (LLD) & Sequence Workflows](#4-low-level-design-lld--sequence-workflows)
   - [4.1 Active Session Enumeration (`GET /api/v1/auth/sessions`)](#41-active-session-enumeration-get-apiv1authsessions)
   - [4.2 Single Remote Session Termination (`DELETE /api/v1/auth/sessions/:id`)](#42-single-remote-session-termination-delete-apiv1authsessionsid)
   - [4.3 Sign Out All Other Devices (`DELETE /api/v1/auth/sessions`)](#43-sign-out-all-other-devices-delete-apiv1authsessions)
5. [Entity Topology & Database Relationships (ERD)](#5-entity-topology--database-relationships-erd)
6. [Finite State Machine & Session Family Lifecycle](#6-finite-state-machine--session-family-lifecycle)
7. [API Contract Specifications & Response Envelopes](#7-api-contract-specifications--response-envelopes)
8. [OpenTelemetry Tracing & Observability](#8-opentelemetry-tracing--observability)
9. [Declarative Configuration Standards (`config/`)](#9-declarative-configuration-standards-config)
10. [Security Invariants & Anti-Tampering Rules](#10-security-invariants--anti-tampering-rules)

---

## 1. Context & Problem Statement

Modern enterprise operators and SaaS users authenticate from multiple physical and virtual endpoints simultaneously: office workstations, laptops, mobile phones, and shared jump hosts. If an active device is stolen, an unencrypted laptop compromised, or a browser profile exfiltrated, adversaries can persist across long-lived refresh token rotation cycles.

In `@observability/auth`, session persistence is anchored on RFC 6749 §10.4 refresh token families (`auth_refresh_token_families` and `auth_refresh_tokens` introduced in ADR 0014). However, before this specification, users had zero ambient visibility into what devices were active under their identity and had no self-service mechanism to remotely revoke suspicious sessions.

### Key Deficiencies Addressed:
1. **Zero Device Visibility**: Users could not see active IP addresses, user agents, or last activity timestamps.
2. **Missing Remote Revocation**: Compromised devices could only be invalidated by destroying all credentials or manually contacting security operations.
3. **Absence of Current Device Preservation**: A standard sign-out or blanket token purge would disconnect the user's active window, breaking administrative workflows.

---

## 2. Decision Drivers

1. **OWASP ASVS 4.0 §3.3 Compliance**:
   - Provide an authenticated endpoint for users to view all currently active concurrent sessions.
   - Permit selective termination of any remote session without impacting the current user agent.
   - Permit atomic "Sign Out All Other Devices" to mitigate credential harvesting after password changes or security alerts.
2. **Current-Session Identity Resolution**:
   - Identify the requesting client's active family from incoming JWT / session context, flagging `is_current: true` for the active session and `is_current: false` for remote devices.
3. **Strict Tenant and Subject Isolation**:
   - Prevent cross-tenant and cross-subject revocation. A user can only view and terminate their own sessions.
4. **Hexagonal Architecture & Zero Inline Comments**:
   - Pure domain services, repository ports, zero magic strings, and strict conformance with `4-functions-and-classes-writing-rule.md` and `06-writing-conditions.md`.

---

## 3. High-Level Design (HLD) & Architectural Topology

```mermaid
flowchart TD
    subgraph Client["User Clients"]
        Laptop["Active Laptop (Current Device)"]
        Mobile["Remote Phone (Stolen Device)"]
        Workstation["Remote Desktop (Office Workstation)"]
    end

    subgraph Gateway["REST Ingress Gateway"]
        Router["AuthRestV1Router<br/>Routes: /api/v1/auth/sessions"]
        AuthGuard["Bearer JWT Session Verification<br/>Extract userId, session family"]
    end

    subgraph ServiceLayer["Domain Orchestration"]
        SessionService["SessionDomainService<br/>- listSessions(userId, currentFamilyId)<br/>- revokeSession(userId, targetFamilyId)<br/>- revokeAllOtherSessions(userId, currentFamilyId)"]
    end

    subgraph Storage["Persistence & Cache"]
        Postgres["PostgreSQL / AlloyDB Omni<br/>auth_refresh_token_families<br/>auth_refresh_tokens"]
        Redis["Redis Cache Adapter<br/>Stateless Token Denylist"]
    end

    Laptop -->|"GET /api/v1/auth/sessions"| Router
    Laptop -->|"DELETE /api/v1/auth/sessions/:id"| Router
    Laptop -->|"DELETE /api/v1/auth/sessions"| Router
    Router --> AuthGuard
    AuthGuard --> SessionService
    SessionService --> Postgres
    SessionService --> Redis
```

---

## 4. Low-Level Design (LLD) & Sequence Workflows

### 4.1 Active Session Enumeration (`GET /api/v1/auth/sessions`)

```mermaid
sequenceDiagram
    autonumber
    participant Client as Authenticated Client (Active Window)
    participant Router as AuthRestV1Router
    participant Service as SessionDomainService
    participant Repo as AuthRepositoryPort
    participant OTEL as OpenTelemetry Tracer

    Client->>Router: GET /api/v1/auth/sessions (Bearer JWT)
    Router->>OTEL: Start Active Span ("REST GET /api/v1/auth/sessions")
    Router->>Router: Verify Session & Extract userId
    Router->>Service: listUserSessions(userId, currentFamilyId)
    Service->>Repo: listActiveSessionsByUserId(userId)
    Repo-->>Service: Active Families & Most Recent Token Metadata
    Service->>Service: Map to UserSessionSummary (Format ISO 8601, Flag is_current)
    Service-->>Router: Result.ok(sessions)
    Router->>OTEL: Set Status OK & End Span
    Router-->>Client: HTTP 200 OK (StandardApiResponse Envelope)
```

### 4.2 Single Remote Session Termination (`DELETE /api/v1/auth/sessions/:id`)

```mermaid
sequenceDiagram
    autonumber
    participant Client as Authenticated Client
    participant Router as AuthRestV1Router
    participant Service as SessionDomainService
    participant Repo as AuthRepositoryPort

    Client->>Router: DELETE /api/v1/auth/sessions/:id (Bearer JWT)
    Router->>Router: Verify Session & Extract userId
    Router->>Service: revokeUserSession(userId, targetFamilyId)
    Service->>Repo: findRefreshTokenFamily(targetFamilyId)
    alt Family Missing or Belonging to Another User
        Repo-->>Service: null or foreign userId
        Service-->>Router: Result.err(NotFoundError / ForbiddenError)
        Router-->>Client: HTTP 404 Not Found
    else Valid Family Owned by User
        Service->>Repo: revokeRefreshTokenFamily(targetFamilyId, "USER_REMOTE_KILL")
        Service-->>Router: Result.ok(void)
        Router-->>Client: HTTP 200 OK ("Session successfully terminated")
    end
```

### 4.3 Sign Out All Other Devices (`DELETE /api/v1/auth/sessions`)

```mermaid
sequenceDiagram
    autonumber
    participant Client as Authenticated Client (Caller Window)
    participant Router as AuthRestV1Router
    participant Service as SessionDomainService
    participant Repo as AuthRepositoryPort

    Client->>Router: DELETE /api/v1/auth/sessions (Bearer JWT)
    Router->>Service: revokeAllOtherSessions(userId, currentFamilyId)
    Service->>Repo: revokeOtherSessionsByUserId(userId, currentFamilyId, "BULK_REMOTE_SIGN_OUT")
    Repo-->>Service: count (number of terminated families)
    Service-->>Router: Result.ok({ revokedCount })
    Router-->>Client: HTTP 200 OK ("Terminated N remote session(s)")
```

---

## 5. Entity Topology & Database Relationships (ERD)

```mermaid
erDiagram
    auth_users ||--o{ auth_refresh_token_families : "owns"
    auth_refresh_token_families ||--o{ auth_refresh_tokens : "tracks rotation generations"

    auth_users {
        string id PK
        string email
        string name
        string org_id
    }

    auth_refresh_token_families {
        string id PK
        string user_id FK
        bigint created_at_ms
        boolean is_revoked
        string revoked_reason
        timestamp updated_at
    }

    auth_refresh_tokens {
        string token_id PK
        string family_id FK
        string user_id FK
        string token_hash UK
        int generation
        boolean is_revoked
        bigint expires_at_ms
        bigint created_at_ms
        bigint consumed_at_ms
        string created_ip
        string user_agent
    }
```

### 5.2 Migration DDL (`database/migrations/0010_create_refresh_tokens_and_families.sql`)

```sql
CREATE TABLE IF NOT EXISTS auth_refresh_token_families (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    created_at_ms BIGINT NOT NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_reason VARCHAR(255),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_auth_refresh_families_user_id ON auth_refresh_token_families(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_refresh_families_revoked ON auth_refresh_token_families(is_revoked);

CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
    token_id VARCHAR(64) PRIMARY KEY,
    family_id VARCHAR(64) NOT NULL REFERENCES auth_refresh_token_families(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    generation INT NOT NULL DEFAULT 1,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at_ms BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    consumed_at_ms BIGINT,
    created_ip VARCHAR(64),
    user_agent VARCHAR(512)
);

CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_hash ON auth_refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_family_id ON auth_refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_user_id ON auth_refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_expires_at ON auth_refresh_tokens(expires_at_ms);
```

---


## 6. Finite State Machine & Session Family Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Active: Login / Initial Refresh Token Issued
    Active --> Rotated: POST /api/v1/auth/refresh (New Generation Token)
    Rotated --> Active: Successful Single-Use Exchange
    
    Active --> TerminatedBySelf: DELETE /api/v1/auth/sessions/:id (Targeted Remote Kill)
    Active --> TerminatedByBulk: DELETE /api/v1/auth/sessions (All Other Devices)
    Active --> TerminatedOnTheft: Token Reuse Detected (Compromise Invalidation)
    Active --> Expired: expires_at_ms < Date.now()

    TerminatedBySelf --> [*]
    TerminatedByBulk --> [*]
    TerminatedOnTheft --> [*]
    Expired --> [*]
```

---

## 7. API Contract Specifications & Response Envelopes

### 7.1 List Active Sessions
- **Method**: `GET`
- **Path**: `/api/v1/auth/sessions`
- **Headers**:
  - `Authorization: Bearer <JWT>`
- **Response**: `HTTP 200 OK`
```json
{
  "success": true,
  "status": "success",
  "statusCode": 200,
  "message": "Active sessions retrieved successfully",
  "data": [
    {
      "id": "fam_01J9...",
      "ip_address": "127.0.0.1",
      "user_agent": "Mozilla/5.0 (X11; Linux x86_64)...",
      "created_at": "2026-10-14T12:00:00.000Z",
      "last_active_at": "2026-10-14T15:00:00.000Z",
      "is_current": true
    }
  ],
  "meta": {
    "requestId": "req_1791987000",
    "timestamp": "2026-10-14T15:00:01.000Z",
    "apiVersion": "1.0.0"
  }
}
```

### 7.2 Revoke Single Remote Session
- **Method**: `DELETE`
- **Path**: `/api/v1/auth/sessions/:id`
- **Response**: `HTTP 200 OK`
```json
{
  "success": true,
  "status": "success",
  "statusCode": 200,
  "message": "Session fam_01J9... successfully terminated",
  "data": {
    "sessionId": "fam_01J9...",
    "terminated": true
  }
}
```

### 7.3 Revoke All Other Devices
- **Method**: `DELETE`
- **Path**: `/api/v1/auth/sessions`
- **Response**: `HTTP 200 OK`
```json
{
  "success": true,
  "status": "success",
  "statusCode": 200,
  "message": "Successfully signed out of 3 other session(s)",
  "data": {
    "revokedCount": 3
  }
}
```

---

## 8. OpenTelemetry Tracing & Observability

Every session operation is traced with dedicated span attributes:
- `span.setAttribute('session.user_id', userId)`
- `span.setAttribute('session.target_family_id', targetFamilyId)`
- `span.setAttribute('session.revoked_count', count)`

---

## 9. Declarative Configuration Standards (`config/`)

All limits are loaded into `AUTH_CONFIG.session` via declarative environment variables:
```bash
# Session Limits
AUTH_SESSION_MAX_CONCURRENT=10
AUTH_SESSION_INACTIVITY_TTL_SECONDS=604800
```

---

## 10. Security Invariants & Anti-Tampering Rules

1. **Authorization Ownership Gate**: A user cannot terminate a session family that does not belong to their `user_id`. Attempting to do so yields an explicit typed `NotFoundError` or `ForbiddenError`.
2. **Current Device Immunity**: Bulk revocation (`DELETE /api/v1/auth/sessions`) mathematically excludes `currentFamilyId`. The caller's session is never severed.
3. **Zero Magic Strings**: All endpoint paths, query keys, and error codes are declared in shared constants modules.
4. **Zero Inline Comments**: Self-documenting code driven by explicit TypeScript types and file header docblocks.

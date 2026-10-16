<div align="center">

# 🔒 Multi-Tenant Auth Service & 13-Pillar Security Engine

### Traefik-Integrated · AlloyDB Omni RLS · Redis Token Denylist · Hexagonal Ports & Adapters

*A production-grade multi-tenant authentication, RBAC authorization, organization management, context switching, audit logging, 3-tier API key permissions management, user blocking/unblocking/deletion, 30-day backup retention, and 13-pillar security engine — fronted by Traefik Proxy, backed by AlloyDB Omni / PostgreSQL Row Level Security (RLS) and Redis.*

![Status](https://img.shields.io/badge/status-production--ready-brightgreen)
![Architecture](https://img.shields.io/badge/architecture-Hexagonal%20Ports%20%26%20Adapters-blueviolet)
![Gateway](https://img.shields.io/badge/gateway-Traefik%20v2.10-24A1C1)
![Database](https://img.shields.io/badge/database-AlloyDB%20Omni%20%2F%20PostgreSQL-336791)
![Cache](https://img.shields.io/badge/cache-Redis%207-DC382D)
![Tracing](https://img.shields.io/badge/tracing-OpenTelemetry-425CC7)

</div>

---

## 📖 Table of Contents

1. [Executive Summary](#-executive-summary)
2. [High-Level Architecture (HLD)](#-high-level-architecture-hld)
3. [Low-Level Design & Security Flow (LLD)](#-low-level-design--security-flow-lld)
4. [Standardized API Response Envelope](#-standardized-api-response-envelope)
5. [Hexagonal Ports & Adapters Architecture](#-hexagonal-ports--adapters-architecture)
6. [Organization & User Lifecycle Workflow](#-organization--user-lifecycle-workflow)
7. [Database Migrations & N-to-N Multi-Tenancy](#-database-migrations--n-to-n-multi-tenancy)
8. [Architecture Decision Records (ADRs) & Master API Catalog](#-architecture-decision-records-adrs--master-api-catalog)
9. [Automated Live API Curl Test Suite](#-automated-live-api-curl-test-suite)
10. [Production Docker Image Run Commands (`chiefj/llm-obs-auth`)](#-production-docker-image-run-commands)
11. [Verified Vitest Test Suite Execution Results](#-verified-vitest-test-suite-execution-results)
12. [Engineering Feature Roadmap & Pending TODOs](./TODO.md)

---

## 🧭 Executive Summary

The `@observability/auth` platform provides enterprise multi-tenant user sign-up, organization isolation, multi-org context switching, role-based access control (RBAC), user blocking/unblocking, soft deletion with 30-day backup retention lifecycle, server-side JWT session invalidation via Redis denylist, 3-tier API key management with permission table binding, and comprehensive audit logging with parameter filtering.

---

## 🏛 High-Level Architecture (HLD)

The Auth service follows **Hexagonal Architecture (Ports & Adapters)**, completely separating HTTP REST delivery and database persistence from core auth & security logic.

```mermaid
flowchart TD
    subgraph Clients["Client Layer"]
        WebApp["Next.js Web App (:31400)"]
        ExternalAPI["External API Consumer"]
    end

    subgraph Gateway["Gateway & Proxy Layer"]
        Traefik["Traefik API Gateway (:31410 / :31411)"]
    end

    subgraph AuthModule["@observability/auth Service (:3001)"]
        Router["AuthRestV1Router"]
        Handlers["Request Handlers"]
        AuthCore["AuthService (Domain Core Engine)"]
        SecurityEngine["13-Pillar Security Engine"]
        Tracer["OpenTelemetry Tracer Middleware"]

        Router --> Handlers
        Handlers --> AuthCore
        AuthCore --> SecurityEngine
        AuthCore --> Tracer
    end

    subgraph InfrastructureLayer["Infrastructure Adapters & Storage"]
        AuthDB[("AlloyDB Omni / PostgreSQL (:31412)")]
        RedisStore[("Redis Token Denylist (:31413)")]
        KafkaBroker["Kafka Messaging Broker (:31414)"]
        OTelCollector["OTel Collector (:31417 / :31418)"]
    end

    %% Flow connections
    WebApp -->|HTTP / REST| Traefik
    ExternalAPI -->|API Key Auth| Traefik
    Traefik -->|Route /api/v1/auth| Router

    AuthCore -->|SQL via Postgres Adapter| AuthDB
    AuthCore -->|Revocation Check| RedisStore
    AuthCore -->|Publish Auth Events| KafkaBroker
    Tracer -->|Send Spans| OTelCollector
```

---

## 🔬 Low-Level Design & Security Flow (LLD)

### 1. Dual-Phase Authentication & Session Validation Pipeline

```mermaid
sequenceDiagram
    autonumber
    participant Client as Client Application
    participant Router as REST Router
    participant Service as AuthService Engine
    participant Redis as Redis Denylist (:31413)
    participant DB as AlloyDB / Postgres (:31412)
    participant OTel as OpenTelemetry Collector

    Note over Client, DB: Phase 1: Authentication & Token Generation
    Client->>Router: POST /api/v1/auth/sign-in
    Router->>Service: handleSignIn(email, password)
    Service->>DB: Fetch user & verify Argon2id hash
    DB-->>Service: User record & org metadata
    Service->>Service: Issue Scoped JWT (sub, org_id, role)
    Service-->>Router: JWT Token & Session Payload
    Router-->>Client: HTTP 200 { status: "success", token: "..." }

    Note over Client, DB: Phase 2: Protected Request & Token Revocation Verification
    Client->>Router: GET /api/v1/auth/organizations (Bearer JWT)
    Router->>Service: handleVerifySession(authHeader)
    Service->>Redis: GET denylist:{token_id}
    alt Token is revoked (Found in Redis)
        Redis-->>Service: Token Revoked Flag
        Service-->>Router: Throw AuthError (UNAUTHORIZED)
        Router-->>Client: HTTP 401 { error: "TOKEN_REVOKED" }
    else Token is active
        Redis-->>Service: Null
        Service->>DB: Query orgs with Tenant Context
        DB-->>Service: Organization Records
        Service->>OTel: Emit Audit Span
        Service-->>Router: Success Response
        Router-->>Client: HTTP 200 { data: [...] }
    end
```

---

## 📦 Standardized API Response Envelope

### Success Envelope (`HTTP 200 / 201`)
```json
{
  "status": "success",
  "message": "Operation completed successfully",
  "data": { ... },
  "error": null
}
```

### Failure Envelope (`HTTP 400 / 401 / 403 / 404 / 409 / 429 / 500`)
```json
{
  "status": "error",
  "message": "Error description message",
  "data": null,
  "error": {
    "code": "ERROR_CODE_NAME",
    "details": "Detailed error context"
  }
}
```

---

## 🗄️ Database Migrations & N-to-N Multi-Tenancy

All database interactions are 100% data-driven and powered by centralized SQL queries defined in [`auth.queries.ts`](./src/features/auth/queries/auth.queries.ts).

| Migration | Description | Table(s) Affected |
|---|---|---|
| `0001_create_auth_tables.sql` | Initial schema setup for multi-tenant auth module with RLS | `auth_organizations`, `auth_users`, `auth_api_keys`, `auth_audit_logs`, `auth_password_resets` |
| `0002_add_indexes_on_all_ids_and_keys.sql` | High-performance B-tree indexes on lookup columns | Index additions across all tables |
| `0003_add_audit_and_soft_delete_columns.sql` | Soft-delete columns (`deleted_at`, `updated_at`) | Column alterations across all tables |
| `0004_add_organization_user_block_soft_delete_cascade.sql` | User blocking, custom permissions array, cascade soft-delete | `auth_users`, `auth_organizations` |
| `0005_create_token_denylist.sql` | Server-side JWT session revocation table | `auth_token_denylist` |
| `0006_create_user_organizations_mapping.sql` | Multi-tenant user-organization N-to-N mapping for org switching | `auth_user_organizations` |

---

## 📐 Architecture Decision Records (ADRs) & Master API Catalog

All architecture specifications, production tuning parameters, data models, and API contracts are formally governed by our **Architecture Decision Records (ADRs)** located in [`auth/adr/`](./adr/README.md).

The complete reference for all **34 API endpoints** — including request parameters, validation schemas, HTTP success/error envelopes, and executable cURL commands — is documented in [**ADR 0008: Master API Catalog**](./adr/0008-master-api-catalog-parameter-contracts-and-response-envelopes.md).

### Architecture Decision Records Index

| Document | Title | Scope / Key Focus | Status |
|---|---|---|---|
| [**ADR 0001**](./adr/0001-hexagonal-architecture-and-rule-engine-router.md) | Hexagonal Architecture & Declarative Rule Engine Router | Ports & Adapters separation, Rule Engine route matching, OpenTelemetry span wrapping | Accepted |
| [**ADR 0002**](./adr/0002-authentication-user-registration-and-signin-flow.md) | Sign-Up, Sign-In, Argon2id Hashing & Audit Logging | Dual-phase authentication flow, Argon2id hash validation, Audit trail capture, Full Call Stack | Accepted |
| [**ADR 0003**](./adr/0003-multi-tenant-organization-switching-and-rls.md) | N-to-N Multi-Tenancy & Org Context Switching | Row-Level Security (RLS), multi-tenant org switching, JWT claim re-issuance | Accepted |
| [**ADR 0004**](./adr/0004-session-revocation-redis-token-denylist.md) | Redis Token Denylist & Session Lifetime Management | Server-side JWT session invalidation, Redis O(1) denylist lookup, 401 auto-logout | Accepted |
| [**ADR 0005**](./adr/0005-opentelemetry-end-to-end-auth-tracing-and-middleware.md) | OpenTelemetry End-to-End Authentication Tracing & Middleware | NodeTracerProvider OTLP exporter, traceHttpMiddleware, W3C trace propagation, Tempo integration | Accepted |
| [**ADR 0006**](./adr/0006-kafka-messaging-pipeline-and-distributed-tracing.md) | Kafka Messaging Pipeline & Distributed Tracing Architecture | Centralized Kafka client, Producer/Consumer middleware pipelines, W3C message header propagation | Accepted |
| [**ADR 0007**](./adr/0007-alloydb-omni-resource-constraints-and-oltp-tuning.md) | AlloyDB Omni Resource Constraints, Memory Optimization & OLTP Tuning | Memory limits, disabling columnar engine, shared_buffers sizing, and preventing g_term_it OOM kills | Accepted |
| [**ADR 0008**](./adr/0008-master-api-catalog-parameter-contracts-and-response-envelopes.md) | Master API Catalog, Parameter Contracts & Response Envelopes | Complete reference for all 34 endpoints, schemas, parameters, success/error envelopes, and live curl verification | Accepted |
| [**ADR 0009**](./adr/0009-docker-production-image-optimization-tree-shaking-and-v8-memory-tuning.md) | Docker Production Image Optimization, Tree-Shaking & V8 Memory Tuning | Multi-stage build, esbuild tree-shaking, node:26-alpine preservation, -99% app layer, 32MB RAM, and Docker Hub deployment | Accepted |
| [**Troubleshooting Guide**](./docs/troubleshooting-and-grafana-guide.md) | Troubleshooting & Grafana Tempo Debugging Guide | TraceQL queries, Grafana setup, time-range filtering, error debugging & fixes | Active Guide |

👉 **For the complete catalog of all 34 endpoints and sample curl requests, see [ADR 0008: Master API Catalog](./adr/0008-master-api-catalog-parameter-contracts-and-response-envelopes.md).**

---

## 📄 OpenAPI 3.0 Contract & Swagger Documentation

The full declarative API contract specifying every request body, query parameter, HTTP success envelope, and typed error code is published under OpenAPI 3.0.3:

- **Local OpenAPI File**: [`contracts/openapi/v1.yaml`](./contracts/openapi/v1.yaml)
- **Live OpenAPI Spec Endpoint**: [http://localhost:3001/openapi.yaml](http://localhost:3001/openapi.yaml)
- **Live Documentation Metadata**: [http://localhost:3001/docs](http://localhost:3001/docs)
- **Interactive Swagger Viewer**: [https://editor.swagger.io/?url=http://localhost:3001/openapi.yaml](https://editor.swagger.io/?url=http://localhost:3001/openapi.yaml)

All endpoints strictly adhere to the unified envelope structure:
```json
{
  "success": true,
  "status": "success",
  "statusCode": 200,
  "message": "Resource retrieved successfully",
  "data": { ... },
  "error": null,
  "meta": {
    "requestId": "req_1792150314097",
    "correlationId": "req_1792150314097",
    "timestamp": "2026-10-16T11:31:54.109Z",
    "executionTimeMs": 13,
    "apiVersion": "1.0.0"
  }
}
```

---

## ⚡ Automated Live API Curl Test Suite

To run and verify all live `curl` API endpoints against the running server:

```bash
npm run test:curl
```

## 🐳 Production Docker Image Run Commands (`chiefj/llm-obs-auth`)

The `@observability/auth` service is packaged as an optimized, tree-shaken, standalone production Docker image based on `node:26-alpine` consuming only **~32 MiB RAM** in steady-state operation.

### 1. Pull Latest Image from Docker Hub

```bash
docker pull chiefj/llm-obs-auth:latest
```

### 2. Standalone Container Run Command

Run as a single container connected to the internal bridge network (`llmobs-network`):

```bash
docker run -d \
  --name observability-auth-service \
  --network llmobs-network \
  -p 3001:3001 \
  -e NODE_ENV=production \
  -e PORT=3001 \
  -e USE_REAL_DB=true \
  -e DATABASE_URL="postgresql://postgres:postgres@auth-service-db:5432/observability_auth" \
  -e REDIS_URL="redis://:llmobs_redis_s3cret_2024@llmobs-redis-ledger:6379" \
  -e KAFKA_BROKERS="llmobs-kafka-broker:9092" \
  -e JWT_SECRET="super-secure-production-auth-jwt-secret-key-replace-in-env-file-minimum-32-chars!" \
  -e SERVICE_REGISTRY_URL="http://llmobs-service-registry:31426" \
  -e OTEL_EXPORTER_OTLP_ENDPOINT="http://llmobs-otel-collector:4318" \
  --restart unless-stopped \
  chiefj/llm-obs-auth:latest
```

### 3. Run with Docker Compose

To launch the Auth service along with AlloyDB Omni using [`auth/docker-compose.yml`](./docker-compose.yml):

```bash
# From repository root
docker compose -f auth/docker-compose.yml up -d
```

### 4. Verify Service Health via cURL

```bash
curl -s http://localhost:3001/api/v1/auth/permissions | jq .
```

Expected output:
```json
{
  "status": "success",
  "message": "System permissions retrieved",
  "data": {
    "permissions": [
      "traces:read",
      "traces:write",
      "metrics:read",
      "metrics:write",
      "logs:read",
      "logs:write",
      "alerts:read",
      "alerts:write",
      "admin:all"
    ]
  },
  "error": null
}
```

### 5. Production Image Specifications & Resource Footprint

| Metric | Measured Value | Architecture Detail |
|---|---|---|
| **Docker Hub Repository** | `chiefj/llm-obs-auth` | Published tags: `latest`, `1.0.0` |
| **Base Operating System** | `node:26-alpine` | Preserved standard Alpine runtime |
| **Total Disk Image Size** | **172.27 MB** | Reduced by **-54.7%** (from 380.58 MB) |
| **Application Layer Size** | **2.01 MB** | Reduced by **-99.04%** via `esbuild` bundling |
| **Compressed Download Size** | **~55 MB** | Rapid cluster pull / scaling transfer |
| **Runtime Memory (RSS)** | **30.2 - 32.2 MiB** | Compacted via V8 `--optimize-for-size --max-old-space-size=128` |

---

## 🧪 Verified Vitest Test Suite Execution Results

All test suites passing cleanly across domain, ports, adapters, database, and OpenAPI contracts.

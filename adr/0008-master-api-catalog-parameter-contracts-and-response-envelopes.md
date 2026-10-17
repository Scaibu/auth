# 📐 ADR 0008: Master API Catalog, Parameter Contracts & Response Envelopes

- **Status**: Accepted
- **Date**: 2026-09-06
- **Authors**: Core Architecture & Security Engineering Team
- **Deciders**: Platform Architecture Board, SecOps, API Governance
- **Correlating Service**: `@observability/auth` (:3001)

---

## 1. Context & Problem Statement

As `@observability/auth` matured into a unified multi-tenant authentication engine serving the Next.js web application, Traefik API gateway, and downstream microservices, the API surface grew to 34 distinct endpoints across 7 functional pillars. Without an authoritative, exhaustive Architecture Decision Record defining every parameter, schema validation rule, query filter, and standard response envelope, integration risks arise across clients, SDKs, and proxies.

This ADR serves as the definitive reference specification for all 34 active HTTP endpoints in `@observability/auth`, detailing exact cURL commands, path parameters, headers, query parameters, request bodies, success envelopes, error envelopes, and RBAC requirements.

---

## 2. Standardized Global Envelopes

All endpoints in `@observability/auth` return RFC-compliant JSON adhering to a standardized response envelope. Clients never parse raw un-enveloped arrays or primitives.

### 2.1 Standard Success Envelope (HTTP 200 / 201)

```json
{
  "status": "success",
  "message": "Human-readable description of operation result",
  "data": { ... },
  "error": null
}
```

### 2.2 Standard Error Envelope (HTTP 400 / 401 / 403 / 404 / 409 / 500)

```json
{
  "status": "error",
  "message": "Human-readable error description",
  "data": null,
  "error": {
    "code": "VALIDATION_ERROR | INVALID_CREDENTIALS | TOKEN_EXPIRED | FORBIDDEN | NOT_FOUND | CONFLICT",
    "message": "Detailed technical failure reason",
    "details": [ ... ]
  }
}
```

### 2.3 Global Standard Headers

| Header | Type | Required | Description |
|---|---|---|---|
| `Content-Type` | `string` | For POST/PATCH | Must be `application/json` |
| `Authorization` | `string` | For Protected Routes | `Bearer <JWT_TOKEN>` |
| `X-Forwarded-For` | `string` | Optional | Client IP address captured for audit logging |
| `User-Agent` | `string` | Optional | Client browser/runtime identifier for audit logging |
| `x-request-id` | `string` | Optional | Tracing correlation ID propagated to OpenTelemetry span |
| `x-tenant-id` | `string` | Optional | Active tenant context override |

---

## 3. Master API Catalog & Executable cURL Specifications (All 34 Endpoints)

---

### 3.1 Pillar 1: Health & System Diagnostics

#### `[1] GET /`
- **Name**: Root Service Check
- **Auth Required**: No (Public)
- **cURL Command**:
```bash
curl -s -X GET "http://localhost:3001/" \
  -H "Accept: application/json"
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "Auth Service API v1 is live",
  "data": {
    "service": "auth-service",
    "version": "1.0.0",
    "status": "healthy"
  },
  "error": null
}
```

#### `[2] GET /health`
- **Name**: Standard Container Health Check
- **Auth Required**: No (Public)
- **cURL Command**:
```bash
curl -s -X GET "http://localhost:3001/health" \
  -H "Accept: application/json"
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "Auth service is healthy",
  "data": {
    "status": "ok"
  },
  "error": null
}
```

#### `[3] GET /api/v1/auth/health`
- **Name**: V1 Versioned Health Check
- **Auth Required**: No (Public)
- **cURL Command**:
```bash
curl -s -X GET "http://localhost:3001/api/v1/auth/health" \
  -H "Accept: application/json"
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "Auth service is healthy",
  "data": {
    "status": "ok"
  },
  "error": null
}
```

---

### 3.2 Pillar 2: Core Authentication & Sessions

#### `[4] POST /api/v1/auth/sign-up`
- **Name**: Combined User & Organization Registration
- **Auth Required**: No (Public)
- **cURL Command**:
```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/sign-up" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@observability.io",
    "password": "StrongPassword123!",
    "name": "Primary Admin",
    "organization_name": "Acme Global",
    "role": "admin"
  }'
```
- **Validation Constraints**:
  - `email`: Valid RFC 5322 email string.
  - `password`: Minimum 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special character (`!@#$%^&*`).
  - `name`: String, minimum 2 characters.
  - `organization_name`: String, minimum 2 characters.
- **Success Response (201 Created)**:
```json
{
  "status": "success",
  "message": "User and organization successfully registered",
  "data": {
    "token": "eyJzdWIiOiJ1c3JfM3ZwbTBqciIsImVtYWlsIjoiYWRtaW5Ab2JzZXJ2YWJpbGl0eS5pbyIsIm9yZyI6eyJvcmdfaWQiOiJvcmdfd3VwMXM2ciIsIm9yZ19uYW1lIjoiQWNtZSBHbG9iYWwiLCJyb2xlIjoiYWRtaW4ifSwiaWF0IjoxNzg4Njk2MTk0LCJleHAiOjE3ODg2OTk3OTR9.c2lnX3Vzcl8zdnBtMGpyXzE3ODg2OTYxOTQ=",
    "user": {
      "id": "usr_3vpm0jr",
      "email": "admin@observability.io",
      "name": "Primary Admin",
      "org_id": "org_wup1s6r",
      "org_name": "Acme Global",
      "role": "admin",
      "blocked": false,
      "user_permissions": []
    }
  },
  "error": null
}
```

#### `[5] POST /api/v1/auth/sign-in`
- **Name**: User Authentication (Argon2id)
- **Auth Required**: No (Public)
- **cURL Command**:
```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/sign-in" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 198.51.100.24" \
  -H "User-Agent: Mozilla/5.0 (ClientApp/1.0)" \
  -d '{
    "email": "admin@observability.io",
    "password": "StrongPassword123!"
  }'
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "User signed in successfully",
  "data": {
    "token": "eyJzdWIiOiJ1c3JfM3ZwbTBqciIsImVtYWlsIjoiYWRtaW5Ab2JzZXJ2YWJpbGl0eS5pbyIsIm9yZyI6eyJvcmdfaWQiOiJvcmdfd3VwMXM2ciIsIm9yZ19uYW1lIjoiQWNtZSBHbG9iYWwiLCJyb2xlIjoiYWRtaW4ifSwiaWF0IjoxNzg4Njk2MTk0LCJleHAiOjE3ODg2OTk3OTR9.c2lnX3Vzcl8zdnBtMGpyXzE3ODg2OTYxOTQ=",
    "user": {
      "id": "usr_3vpm0jr",
      "email": "admin@observability.io",
      "name": "Primary Admin",
      "org_id": "org_wup1s6r",
      "org_name": "Acme Global",
      "role": "admin",
      "blocked": false,
      "user_permissions": []
    }
  },
  "error": null
}
```

#### `[6] GET /api/v1/auth/session`
- **Name**: Verify Session Token Validity
- **Auth Required**: Yes (`Bearer <token>`)
- **cURL Command**:
```bash
curl -s -X GET "http://localhost:3001/api/v1/auth/session" \
  -H "Authorization: Bearer eyJzdWIiOiJ1c3JfM3ZwbTBqciIsImVtYWlsIjoiYWRtaW5Ab2JzZXJ2YWJpbGl0eS5pbyIsIm9yZyI6eyJvcmdfaWQiOiJvcmdfd3VwMXM2ciIsIm9yZ19uYW1lIjoiQWNtZSBHbG9iYWwiLCJyb2xlIjoiYWRtaW4ifSwiaWF0IjoxNzg4Njk2MTk0LCJleHAiOjE3ODg2OTk3OTR9.c2lnX3Vzcl8zdnBtMGpyXzE3ODg2OTYxOTQ="
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "Session token verified",
  "data": {
    "sub": "usr_3vpm0jr",
    "email": "admin@observability.io",
    "org": {
      "org_id": "org_wup1s6r",
      "org_name": "Acme Global",
      "role": "admin"
    },
    "iat": 1788696194,
    "exp": 1788699794
  },
  "error": null
}
```

#### `[7] POST /api/v1/auth/sign-out`
- **Name**: Sign Out & Invalidate Session
- **Auth Required**: Yes (`Bearer <token>`)
- **cURL Command**:
```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/sign-out" \
  -H "Authorization: Bearer eyJzdWIiOiJ1c3JfM3ZwbTBqciIsImVtYWlsIjoiYWRtaW5Ab2JzZXJ2YWJpbGl0eS5pbyIsIm9yZyI6eyJvcmdfaWQiOiJvcmdfd3VwMXM2ciIsIm9yZ19uYW1lIjoiQWNtZSBHbG9iYWwiLCJyb2xlIjoiYWRtaW4ifSwiaWF0IjoxNzg4Njk2MTk0LCJleHAiOjE3ODg2OTk3OTR9.c2lnX3Vzcl8zdnBtMGpyXzE3ODg2OTYxOTQ="
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "Signed out successfully",
  "data": null,
  "error": null
}
```

---

### 3.3 Pillar 3: Password Lifecycle Management

#### `[8] POST /api/v1/auth/forgot-password`
- **Name**: Request Password Reset Token
- **Auth Required**: No (Public)
- **cURL Command**:
```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@observability.io"
  }'
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "Password reset request processed",
  "data": {
    "resetToken": "rst_4i928bcmxk1"
  },
  "error": null
}
```

#### `[9] POST /api/v1/auth/reset-password`
- **Name**: Reset Password with Token
- **Auth Required**: No (Public)
- **cURL Command**:
```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/reset-password" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "rst_4i928bcmxk1",
    "new_password": "NewStrongPassword456!"
  }'
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "Password successfully reset",
  "data": {
    "success": true
  },
  "error": null
}
```

#### `[10] POST /api/v1/auth/change-password`
- **Name**: Authenticated Password Change
- **Auth Required**: Yes (`Bearer <token>`)
- **cURL Command**:
```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/change-password" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "StrongPassword123!",
    "new_password": "NewStrongPassword456!"
  }'
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "Password successfully changed",
  "data": {
    "success": true
  },
  "error": null
}
```

---

### 3.4 Pillar 4: Organization & Multi-Tenancy

#### `[11] POST /api/v1/auth/organizations`
- **Name**: Create Secondary Organization
- **Auth Required**: Yes (`Bearer <token>`)
- **cURL Command**:
```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/organizations" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Research Labs"
  }'
```
- **Success Response (201 Created)**:
```json
{
  "status": "success",
  "message": "Organization created successfully",
  "data": {
    "id": "org_r5wl4s7",
    "name": "Acme Research Labs",
    "slug": "acme-research-labs"
  },
  "error": null
}
```

#### `[12] GET /api/v1/auth/organizations`
- **Name**: List Organizations for Authenticated User
- **Auth Required**: Yes (`Bearer <token>`)
- **cURL Command**:
```bash
curl -s -X GET "http://localhost:3001/api/v1/auth/organizations" \
  -H "Authorization: Bearer <TOKEN>"
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "Organizations retrieved",
  "data": [
    {
      "id": "org_wup1s6r",
      "name": "Acme Global",
      "slug": "acme-global",
      "role": "admin"
    },
    {
      "id": "org_r5wl4s7",
      "name": "Acme Research Labs",
      "slug": "acme-research-labs",
      "role": "owner"
    }
  ],
  "error": null
}
```

#### `[13] GET /api/v1/auth/organizations/:id`
- **Name**: Get Organization by ID
- **Auth Required**: No (Public / Internal)
- **cURL Command**:
```bash
curl -s -X GET "http://localhost:3001/api/v1/auth/organizations/org_r5wl4s7"
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "Organization retrieved",
  "data": {
    "id": "org_r5wl4s7",
    "name": "Acme Research Labs",
    "slug": "acme-research-labs"
  },
  "error": null
}
```

#### `[14] PATCH /api/v1/auth/organizations/:id`
- **Name**: Update Organization
- **Auth Required**: No (Public / Internal)
- **cURL Command**:
```bash
curl -s -X PATCH "http://localhost:3001/api/v1/auth/organizations/org_r5wl4s7" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Advanced Research"
  }'
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "Organization updated",
  "data": {
    "id": "org_r5wl4s7",
    "name": "Acme Advanced Research",
    "slug": "acme-research-labs"
  },
  "error": null
}
```

#### `[15] POST /api/v1/auth/organizations/:id/switch`
- **Name**: Switch Organization Context
- **Auth Required**: Yes (`Bearer <token>`)
- **cURL Command**:
```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/organizations/org_r5wl4s7/switch" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json"
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "Organization context switched",
  "data": {
    "token": "eyJzdWIiOiJ1c3JfM3ZwbTBqciIsImVtYWlsIjoiYWRtaW5Ab2JzZXJ2YWJpbGl0eS5pbyIsIm9yZyI6eyJvcmdfaWQiOiJvcmdfcjV3bDRzNyIsIm9yZ19uYW1lIjoiQWNtZSBBZHZhbmNlZCBSZXNlYXJjaCIsInJvbGUiOiJhZG1pbiJ9LCJpYXQiOjE3ODg2OTYxOTUsImV4cCI6MTc4ODY5OTc5NX0=.c2lnX3Vzcl8zdnBtMGpyXzE3ODg2OTYxOTU=",
    "payload": {
      "sub": "usr_3vpm0jr",
      "email": "admin@observability.io",
      "org": {
        "org_id": "org_r5wl4s7",
        "org_name": "Acme Advanced Research",
        "role": "admin"
      },
      "exp": 1788699795,
      "iat": 1788696195
    }
  },
  "error": null
}
```

#### `[16] DELETE /api/v1/auth/organizations/:id`
- **Name**: Soft-Delete Organization (30-Day Retention)
- **Auth Required**: No (Public / Internal)
- **cURL Command**:
```bash
curl -s -X DELETE "http://localhost:3001/api/v1/auth/organizations/org_r5wl4s7"
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "Organization soft-deleted with 30-day backup retention",
  "data": {
    "success": true,
    "message": "Organization org_r5wl4s7 and all associated entity details soft-deleted with 30-day backup retention."
  },
  "error": null
}
```

---

### 3.5 Pillar 5: User Lifecycle & Access Control

#### `[17] GET /api/v1/auth/users/me`
- **Name**: Get Current User Profile
- **Auth Required**: Yes (`Bearer <token>`)
- **cURL Command**:
```bash
curl -s -X GET "http://localhost:3001/api/v1/auth/users/me" \
  -H "Authorization: Bearer <TOKEN>"
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "User profile retrieved",
  "data": {
    "id": "usr_3vpm0jr",
    "email": "admin@observability.io",
    "name": "Primary Admin",
    "org_id": "org_wup1s6r",
    "org_name": "Acme Global",
    "role": "admin",
    "blocked": false,
    "user_permissions": []
  },
  "error": null
}
```

#### `[18] PATCH /api/v1/auth/users/me`
- **Name**: Update Current User Profile
- **Auth Required**: Yes (`Bearer <token>`)
- **cURL Command**:
```bash
curl -s -X PATCH "http://localhost:3001/api/v1/auth/users/me" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Admin Name"
  }'
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "User profile updated",
  "data": {
    "id": "usr_3vpm0jr",
    "email": "admin@observability.io",
    "name": "Updated Admin Name",
    "org_id": "org_wup1s6r",
    "org_name": "Acme Global",
    "role": "admin",
    "blocked": false,
    "user_permissions": []
  },
  "error": null
}
```

#### `[19] POST /api/v1/auth/users`
- **Name**: Direct Administrative User Creation
- **Auth Required**: No (Public / Internal Service)
- **cURL Command**:
```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/users" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "member_direct@observability.io",
    "password": "StrongPassword123!",
    "name": "Direct Created User",
    "org_id": "org_r5wl4s7",
    "role": "member",
    "permissions": ["traces:read", "metrics:read"]
  }'
```
- **Success Response (201 Created)**:
```json
{
  "status": "success",
  "message": "User created in target organization with specific permissions",
  "data": {
    "id": "usr_tis55zk",
    "email": "member_direct@observability.io",
    "password_hash": "d9d8e7ee4e92681edbb144557bbf512c15e51582ed8f4a03dac98e88d1065674",
    "name": "Direct Created User",
    "org_id": "org_r5wl4s7",
    "org_name": "",
    "role": "member",
    "blocked": false,
    "user_permissions": [
      "traces:read",
      "metrics:read"
    ]
  },
  "error": null
}
```

#### `[20] POST /api/v1/auth/users/invite`
- **Name**: Invite Member to Organization
- **Auth Required**: Yes (`Bearer <token>`)
- **cURL Command**:
```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/users/invite" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "member_invite@observability.io",
    "name": "Invited Member",
    "role": "member",
    "permissions": ["traces:read"]
  }'
```
- **Success Response (201 Created)**:
```json
{
  "status": "success",
  "message": "User invited to organization",
  "data": {
    "id": "usr_3ee4rgp",
    "email": "member_invite@observability.io",
    "password_hash": "1bc8d9423fd655848cc88dfe5aaad848331011b48498aeb0272c5b19bc706bd1",
    "name": "Invited Member",
    "org_id": "org_r5wl4s7",
    "org_name": "Acme Advanced Research",
    "role": "member",
    "blocked": false,
    "user_permissions": [
      "traces:read"
    ]
  },
  "error": null
}
```

#### `[21] GET /api/v1/auth/users`
- **Name**: List Organization Members
- **Auth Required**: Yes (`Bearer <token>`)
- **cURL Command**:
```bash
curl -s -X GET "http://localhost:3001/api/v1/auth/users" \
  -H "Authorization: Bearer <TOKEN>"
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "Members retrieved",
  "data": [
    {
      "id": "usr_tis55zk",
      "email": "member_direct@observability.io",
      "name": "Direct Created User",
      "org_id": "org_r5wl4s7",
      "org_name": "Acme Advanced Research",
      "role": "member",
      "blocked": false,
      "user_permissions": [
        "traces:read",
        "metrics:read"
      ]
    },
    {
      "id": "usr_3ee4rgp",
      "email": "member_invite@observability.io",
      "name": "Invited Member",
      "org_id": "org_r5wl4s7",
      "org_name": "Acme Advanced Research",
      "role": "member",
      "blocked": false,
      "user_permissions": [
        "traces:read"
      ]
    }
  ],
  "error": null
}
```

#### `[22] GET /api/v1/auth/users/:id`
- **Name**: Get User Record by ID
- **Auth Required**: No (Public / Internal)
- **cURL Command**:
```bash
curl -s -X GET "http://localhost:3001/api/v1/auth/users/usr_tis55zk"
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "User retrieved",
  "data": {
    "id": "usr_tis55zk",
    "email": "member_direct@observability.io",
    "password_hash": "d9d8e7ee4e92681edbb144557bbf512c15e51582ed8f4a03dac98e88d1065674",
    "name": "Direct Created User",
    "org_id": "org_r5wl4s7",
    "org_name": "Acme Advanced Research",
    "role": "member",
    "blocked": false,
    "user_permissions": [
      "traces:read",
      "metrics:read"
    ]
  },
  "error": null
}
```

#### `[23] PATCH /api/v1/auth/users/:id/role`
- **Name**: Update Member Role
- **Auth Required**: No (Public / Internal)
- **cURL Command**:
```bash
curl -s -X PATCH "http://localhost:3001/api/v1/auth/users/usr_tis55zk/role" \
  -H "Content-Type: application/json" \
  -d '{
    "role": "admin"
  }'
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "User role updated",
  "data": null,
  "error": null
}
```

#### `[24] GET /api/v1/auth/users/:id/permissions`
- **Name**: Get User Granular Permissions
- **Auth Required**: No (Public / Internal)
- **cURL Command**:
```bash
curl -s -X GET "http://localhost:3001/api/v1/auth/users/usr_tis55zk/permissions"
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "User permissions retrieved",
  "data": [
    "traces:read",
    "metrics:read"
  ],
  "error": null
}
```

#### `[25] PATCH /api/v1/auth/users/:id/permissions`
- **Name**: Update User Granular Permissions
- **Auth Required**: No (Public / Internal)
- **cURL Command**:
```bash
curl -s -X PATCH "http://localhost:3001/api/v1/auth/users/usr_tis55zk/permissions" \
  -H "Content-Type: application/json" \
  -d '{
    "permissions": ["traces:read", "metrics:read", "logs:read"]
  }'
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "User permissions updated",
  "data": null,
  "error": null
}
```

#### `[26] POST /api/v1/auth/users/:id/block`
- **Name**: Administratively Block User Account
- **Auth Required**: No (Public / Internal)
- **cURL Command**:
```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/users/usr_tis55zk/block"
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "User blocked successfully",
  "data": {
    "success": true,
    "message": "User usr_tis55zk blocked successfully."
  },
  "error": null
}
```

#### `[27] DELETE /api/v1/auth/users/:id/unblock`
- **Name**: Unblock User Account
- **Auth Required**: No (Public / Internal)
- **cURL Command**:
```bash
curl -s -X DELETE "http://localhost:3001/api/v1/auth/users/usr_tis55zk/unblock"
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "User unblocked successfully",
  "data": {
    "success": true,
    "message": "User usr_tis55zk unblocked successfully."
  },
  "error": null
}
```

#### `[28] DELETE /api/v1/auth/users/:id`
- **Name**: Soft-Delete User (30-Day Backup Retention)
- **Auth Required**: No (Public / Internal)
- **cURL Command**:
```bash
curl -s -X DELETE "http://localhost:3001/api/v1/auth/users/usr_tis55zk"
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "User soft-deleted with 30-day backup retention",
  "data": {
    "success": true,
    "message": "User usr_tis55zk soft-deleted with 30-day backup retention."
  },
  "error": null
}
```

---

### 3.6 Pillar 6: API Keys & Permissions

#### `[29] GET /api/v1/auth/permissions`
- **Name**: List System Permissions Registry
- **Auth Required**: No (Public)
- **cURL Command**:
```bash
curl -s -X GET "http://localhost:3001/api/v1/auth/permissions"
```
- **Success Response (200 OK)**:
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

#### `[30] POST /api/v1/auth/api-keys (General Tier)`
- **Name**: Create Ingestion API Key (`ak_gen_`)
- **Auth Required**: Yes (`Bearer <token>`)
- **cURL Command**:
```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/api-keys" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "General Ingestion Key",
    "org_id": "org_r5wl4s7",
    "key_type": "general",
    "permissions": ["traces:read", "metrics:read"]
  }'
```
- **Success Response (201 Created)**:
```json
{
  "status": "success",
  "message": "API key successfully created",
  "data": {
    "rawKey": "ak_gen_org_r5wl4s7_8rrtcr6pl641q067z45wm8",
    "keyRecord": {
      "key_id": "key_97v48p7",
      "org_id": "org_r5wl4s7",
      "key_type": "general",
      "key_hash": "adcaf2abd8dec73f809824c363f137bda91138f314ba270699ff26b9e660cf96",
      "prefix": "ak_gen_",
      "name": "General Ingestion Key",
      "permissions": [
        "traces:read",
        "metrics:read"
      ],
      "created_at_ms": 1788696196481,
      "revoked": false
    }
  },
  "error": null
}
```

#### `[31] POST /api/v1/auth/api-keys (Super Secret Tier)`
- **Name**: Create Admin Secret API Key (`ak_sec_`)
- **Auth Required**: Yes (`Bearer <token>`)
- **cURL Command**:
```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/api-keys" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Super Secret Admin Key",
    "org_id": "org_r5wl4s7",
    "key_type": "super_secret",
    "permissions": ["traces:read", "metrics:read", "logs:read"]
  }'
```
- **Success Response (201 Created)**:
```json
{
  "status": "success",
  "message": "API key successfully created",
  "data": {
    "rawKey": "ak_sec_org_r5wl4s7_pzbpje7epkaaye4v8q6iv9",
    "keyRecord": {
      "key_id": "key_j76mrxi",
      "org_id": "org_r5wl4s7",
      "key_type": "super_secret",
      "key_hash": "e8117e06f7d4d3bd0c9c2169ecc66e6ac30e7605829e01004fe949ada546d27b",
      "prefix": "ak_sec_",
      "name": "Super Secret Admin Key",
      "permissions": [
        "traces:read",
        "metrics:read",
        "logs:read"
      ],
      "created_at_ms": 1788696196716,
      "revoked": false
    }
  },
  "error": null
}
```

#### `[32] POST /api/v1/auth/api-keys/verify`
- **Name**: Verify API Key Authenticity & Permissions
- **Auth Required**: No (Public / Gateway Hook)
- **cURL Command**:
```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/api-keys/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "key": "ak_gen_org_r5wl4s7_8rrtcr6pl641q067z45wm8",
    "required_permission": "traces:read"
  }'
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "API key verified",
  "data": {
    "valid": true,
    "record": {
      "key_id": "key_97v48p7",
      "org_id": "org_r5wl4s7",
      "key_type": "general",
      "key_hash": "adcaf2abd8dec73f809824c363f137bda91138f314ba270699ff26b9e660cf96",
      "prefix": "ak_gen_",
      "name": "General Ingestion Key",
      "permissions": [
        "traces:read",
        "metrics:read"
      ],
      "created_at_ms": 1788696196481,
      "revoked": false
    },
    "authorized": true
  },
  "error": null
}
```

#### `[33] GET /api/v1/auth/api-keys`
- **Name**: List Active Organization API Keys
- **Auth Required**: Yes (`Bearer <token>`)
- **cURL Command**:
```bash
curl -s -X GET "http://localhost:3001/api/v1/auth/api-keys" \
  -H "Authorization: Bearer <TOKEN>"
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "API keys retrieved",
  "data": [
    {
      "key_id": "key_97v48p7",
      "org_id": "org_r5wl4s7",
      "key_type": "general",
      "prefix": "ak_gen_",
      "name": "General Ingestion Key",
      "permissions": [
        "traces:read",
        "metrics:read"
      ],
      "created_at_ms": 1788696196481,
      "revoked": false
    },
    {
      "key_id": "key_j76mrxi",
      "org_id": "org_r5wl4s7",
      "key_type": "super_secret",
      "prefix": "ak_sec_",
      "name": "Super Secret Admin Key",
      "permissions": [
        "traces:read",
        "metrics:read",
        "logs:read"
      ],
      "created_at_ms": 1788696196716,
      "revoked": false
    }
  ],
  "error": null
}
```

#### `[34] POST /api/v1/auth/api-keys/:id/revoke`
- **Name**: Revoke API Key
- **Auth Required**: Yes (`Bearer <token>`)
- **cURL Command**:
```bash
curl -s -X POST "http://localhost:3001/api/v1/auth/api-keys/key_97v48p7/revoke" \
  -H "Authorization: Bearer <TOKEN>"
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "API key revoked",
  "data": null,
  "error": null
}
```

---

### 3.7 Pillar 7: Audit Logging & Observability

#### `[BONUS 35] GET /api/v1/auth/audit-logs`
- **Name**: Filtered Audit Event Logs
- **Auth Required**: Yes (`Bearer <token>`)
- **cURL Command**:
```bash
curl -s -X GET "http://localhost:3001/api/v1/auth/audit-logs?event_type=ORG_SWITCH" \
  -H "Authorization: Bearer <TOKEN>"
```
- **Success Response (200 OK)**:
```json
{
  "status": "success",
  "message": "Audit logs retrieved",
  "data": [
    {
      "id": "audit_8oiue2r",
      "user_id": "usr_3vpm0jr",
      "org_id": "org_r5wl4s7",
      "event_type": "ORG_SWITCH",
      "ip_address": "198.51.100.24",
      "user_agent": "CurlE2ETest/1.0",
      "timestamp_ms": 1788696195467
    }
  ],
  "error": null
}
```

---

## 4. Keycloak Migration API Catalog & Contracts

In accordance with the Keycloak delegation architecture, standard OpenID Connect endpoints and Keycloak Admin REST APIs are integrated alongside existing service routes.

### 4.1 Keycloak OpenID Connect Endpoints

#### `POST /realms/{realm}/protocol/openid-connect/token`
- **Purpose**: Authenticate via Resource Owner Password Credentials Grant or exchange Refresh Token.
- **Headers**: `Content-Type: application/x-www-form-urlencoded`
- **Payload Parameters**:
  - `grant_type`: `password` | `refresh_token`
  - `client_id`: OAuth client ID (`auth-service`)
  - `client_secret`: Optional client secret
  - `username`: User email address
  - `password`: User password
  - `scope`: `openid profile email`

#### `POST /realms/{realm}/protocol/openid-connect/revoke`
- **Purpose**: Instant token revocation.
- **Parameters**: `token`, `token_type_hint` (`refresh_token` | `access_token`), `client_id`.

#### `POST /realms/{realm}/protocol/openid-connect/logout`
- **Purpose**: Backchannel or user logout invalidating active Keycloak sessions.
- **Parameters**: `client_id`, `refresh_token`.

#### `GET /realms/{realm}/protocol/openid-connect/certs`
- **Purpose**: Authoritative JSON Web Key Set (JWKS) discovery endpoint providing public EdDSA / RS256 signing keys for cryptographic verification.

## Execution Flow (Call Stack Tree)

```text
createServer(listener: (req: IncomingMessage, res: ServerResponse) => void): Server
└── runWithHttpTracing(req: IncomingMessage, res: ServerResponse, fn: () => Promise<void>): Promise<void>
    └── dispatch(method: string, path: string, body: unknown, headers: Record<string, string>): Promise<RouteDispatchResult>
        ├── matchRoute(method: string, path: string): { rule: RouteRule, params: Record<string, string> } | null
        ├── handler(ctx: RouteContext): Promise<RouteDispatchResult>
        │   dispatch(method: string, path: string, body: unknown, headers: Record<string, string>): Promise<RouteDispatchResult>
        │   ├── matchRoute(method: string, path: string): { rule: RouteRule, params: Record<string, string> } | null
        │   ├── validateSchema(schema: ZodSchema<T>, data: unknown): T
        │   ├── handler(ctx: RouteContext): Promise<TResult>
        │   └── createSuccessResponse(data: TResult, message: string, meta: ResponseMeta): ApiResponse<TResult>
        ├── createSuccessResponse(data: RouteDispatchResult, message: string, meta: ResponseMeta, statusCode: number): ApiResponse<RouteDispatchResult>
        └── end(chunk: string): ServerResponse

// Type Reference:
// ApiResponse<T>      = { success: boolean, statusCode: number, message: string, data: T, meta: ResponseMeta }
// RouteDispatchResult = { statusCode: number, payload: ApiResponse<RouteDispatchResult>, headers: Record<string, string> }
```

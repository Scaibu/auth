# ADR 0042: Immutable WORM Audit Archive (SEC Rule 17a-4(f) / S3 Object Lock)

- **Status**: Accepted
- **Date**: 2026-10-16
- **Author**: Platform Architecture & Security Team
- **Area**: Audit Logging, Regulatory Compliance, Cryptographic Integrity, Tamper-Proof Storage
- **Standards**: [SEC Rule 17a-4(f)](https://www.sec.gov/rules/final/34-44992.htm), [FINRA Rule 4511](https://www.finra.org/rules-guidance/rulebooks/finra-rules/4511), [CFTC Rule 1.31](https://www.cftc.gov/LawRegulation/CommodityExchangeAct/index.htm), [RFC 6962 (Certificate Transparency / Merkle Tree)](https://datatracker.ietf.org/doc/html/rfc6962)

---

## 📑 Table of Contents

1. [Context, Threat Modeling & Regulatory Mandates](#-1-context-threat-modeling--regulatory-mandates)
2. [Architectural Decision & Immutable WORM Pipeline](#-2-architectural-decision--immutable-worm-pipeline)
3. [Configuration & Environment Specification](#-3-configuration--environment-specification)
4. [Database Schema Specification (Migration 0035)](#-4-database-schema-specification-migration-0035)
5. [Hexagonal Architecture & Service Contracts](#-5-hexagonal-architecture--service-contracts)
6. [Merkle Tree Cryptographic Proof Specification](#-6-merkle-tree-cryptographic-proof-specification)
7. [REST API Contracts & Response Envelopes](#-7-rest-api-contracts--response-envelopes)
8. [OpenTelemetry Tracing & Audit Telemetry](#-8-opentelemetry-tracing--audit-telemetry)

---

## 🎯 1. Context, Threat Modeling & Regulatory Mandates

### 1.1 Regulatory Landscape (SEC Rule 17a-4(f) & FINRA Rule 4511)
Regulated financial services, healthcare, and enterprise authentication platforms must store audit records in non-rewritable, non-erasable format (Write-Once-Read-Many, or WORM) for statutory retention periods (typically 6 or 7 years). Key requirements:
- **Tamper Resistance**: Even database administrators, cloud root account holders, and compromised credentials must not be able to delete or modify audit records before their legal retention deadline expires.
- **Verifiable Completeness**: Any auditor or compliance officer must be able to verify that no log entries were injected, omitted, or reordered within an archived segment.
- **Accurate Serialization**: Records must be time-ordered, serialized deterministically, and sealed with cryptographic digests.

### 1.2 Threat Modeling
- **Rogue Administrator**: Database superuser connects and executes `DELETE FROM auth_audit_logs WHERE event_type = 'UNAUTHORIZED_ACCESS'`.
- **Compromised Cold Storage**: Attacker alters archived log files directly in object storage to conceal breach movements.
- **Silent Record Omission**: Adversary removes records during export, resulting in incomplete evidence trails.

---

## ⚙️ 2. Architectural Decision & Immutable WORM Pipeline

### 2.1 The WORM Sealing Lifecycle
1. **Segment Extraction**: An administrative or scheduled job queries unsealed audit logs in a specified time window `[segment_start, segment_end]`.
2. **Canonical Serialization & Merkle Tree**:
   - Each audit entry is serialized into canonical JSON (`{"id":...,"user_id":...,"org_id":...,"event_type":...,"ip_address":...,"user_agent":...,"timestamp_ms":...}`).
   - Leaf hashes are computed via SHA-256 (`SHA-256(canonical_json)`).
   - An append-only Merkle tree is constructed, culminating in a 32-byte hexadecimal **Merkle Root Hash**.
3. **Payload Archival**:
   - The canonical segment is packaged into a compressed NDJSON payload (`application/x-ndjson`).
   - The archive manifest is pushed to Amazon S3 Object Lock (or compatible WORM object storage) in **Compliance Mode** with `ObjectLockRetainUntilDate` set to `NOW() + retention_years`.
4. **Immutability Enforcement**:
   - Once sealed, the record in `auth_audit_worm_archives` transitions to `SEALED` and becomes immutable.
   - Deletion of `auth_audit_worm_archives` rows is prevented via database trigger constraints.

---

## 🔧 3. Configuration & Environment Specification

```bash
# Enable or disable the WORM Audit Archive subsystem (default: true)
AUTH_WORM_ARCHIVE_ENABLED=true

# Storage provider: 's3' (AWS S3 Object Lock), 'gcs' (Bucket Lock), or 'memory' (testing)
AUTH_WORM_STORAGE_PROVIDER=memory

# Default retention period in years (SEC 17a-4 compliance requires >= 6 years; default: 7)
AUTH_WORM_DEFAULT_RETENTION_YEARS=7

# S3 Bucket configured with Object Lock enabled in Compliance Mode
AUTH_WORM_S3_BUCKET=compliance-worm-audit-logs

# S3 Region
AUTH_WORM_S3_REGION=us-east-1

# S3 Key Prefix
AUTH_WORM_S3_KEY_PREFIX=auth/audit-worm/
```

---

## 🗄️ 4. Database Schema Specification (Migration 0035)

```sql
CREATE TABLE IF NOT EXISTS auth_audit_worm_archives (
  id VARCHAR(64) PRIMARY KEY,
  segment_start_ms BIGINT NOT NULL,
  segment_end_ms BIGINT NOT NULL,
  record_count INTEGER NOT NULL,
  merkle_root VARCHAR(64) NOT NULL,
  storage_location VARCHAR(512) NOT NULL,
  storage_version_id VARCHAR(255) NULL,
  retention_until_ms BIGINT NOT NULL,
  status VARCHAR(32) NOT NULL,
  sealed_by_user_id VARCHAR(64) NOT NULL,
  created_at_ms BIGINT NOT NULL,

  CONSTRAINT auth_audit_worm_archives_status_ck CHECK (status IN ('PENDING', 'SEALED', 'FAILED')),
  CONSTRAINT auth_audit_worm_archives_record_count_ck CHECK (record_count > 0),
  CONSTRAINT auth_audit_worm_archives_time_range_ck CHECK (segment_end_ms >= segment_start_ms),
  CONSTRAINT auth_audit_worm_archives_merkle_root_ck CHECK (length(merkle_root) = 64)
);

CREATE INDEX IF NOT EXISTS idx_auth_audit_worm_archives_range
  ON auth_audit_worm_archives (segment_start_ms, segment_end_ms);

CREATE INDEX IF NOT EXISTS idx_auth_audit_worm_archives_status
  ON auth_audit_worm_archives (status);
```

---

## 🌳 5. Merkle Tree Cryptographic Proof Specification

1. **Leaf Node Hashing**:
   $$H_{\text{leaf}} = \text{SHA-256}(\text{"0x00"} \mathbin{\Vert} \text{CanonicalJSON}(record))$$
2. **Intermediate Node Hashing**:
   $$H_{\text{parent}} = \text{SHA-256}(\text{"0x01"} \mathbin{\Vert} H_{\text{left}} \mathbin{\Vert} H_{\text{right}})$$
   - If odd number of leaves, duplicate the last leaf to balance the tree node.
3. **Audit Verification**:
   - Given an archive payload, recompute leaf hashes and Merkle root.
   - If recomputed root matches `merkle_root` stored in the sealed database record, the archive integrity is cryptographically guaranteed.

---

## 🚀 6. REST API Endpoints

- `POST /api/v1/auth/audit/worm/seal`: Initiate sealing of an audit segment window.
- `GET /api/v1/auth/audit/worm/archives`: List sealed WORM archives and verification metadata.
- `GET /api/v1/auth/audit/worm/archives/:id/verify`: Verify cryptographic Merkle root of an archived segment.

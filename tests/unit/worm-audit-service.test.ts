/**
 * @file worm-audit-service.test.ts
 * @description Unit Tests for Immutable WORM Audit Archive & Merkle Tree Verification (SEC Rule 17a-4(f)).
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { WormAuditDomainService } from '../../src/features/auth/services/worm-audit.service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import type { AuditLogRecord } from '../../src/features/auth/types';

describe('WormAuditDomainService', () => {
  let repo: AlloyDBOmniAuthAdapter;
  let service: WormAuditDomainService;

  beforeEach(() => {
    repo = new AlloyDBOmniAuthAdapter();
    service = new WormAuditDomainService(repo);
  });

  it('computes deterministic SHA-256 leaf hashes for audit records', () => {
    const log1: AuditLogRecord = {
      id: 'log_01',
      user_id: 'usr_01',
      org_id: 'org_01',
      event_type: 'USER_LOGIN_SUCCESS',
      ip_address: '192.168.1.10',
      user_agent: 'Mozilla/5.0',
      timestamp_ms: 1700000000000,
    };

    const hash1 = service.computeLeafHash(log1);
    const hash2 = service.computeLeafHash(log1);

    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(64);
  });

  it('computes deterministic Merkle root from leaves', () => {
    const leaves = [
      'a'.repeat(64),
      'b'.repeat(64),
      'c'.repeat(64),
    ];

    const root1 = service.computeMerkleRoot(leaves);
    const root2 = service.computeMerkleRoot(leaves);

    expect(root1).toBe(root2);
    expect(root1).toHaveLength(64);
  });

  it('seals an audit log segment and stores immutable archive metadata', async () => {
    const now = Date.now();
    await repo.recordAuditLog({
      id: 'log_01',
      user_id: 'usr_01',
      org_id: 'org_01',
      event_type: 'USER_LOGIN',
      ip_address: '10.0.0.1',
      user_agent: 'Chrome',
      timestamp_ms: now - 5000,
    });
    await repo.recordAuditLog({
      id: 'log_02',
      user_id: 'usr_02',
      org_id: 'org_01',
      event_type: 'USER_SIGNOUT',
      ip_address: '10.0.0.2',
      user_agent: 'Safari',
      timestamp_ms: now - 1000,
    });

    const archive = await service.sealAuditSegment({
      segment_start_ms: now - 10000,
      segment_end_ms: now,
      retention_years: 7,
      sealed_by_user_id: 'usr_admin',
    });

    expect(archive.id).toMatch(/^worm_arc_/);
    expect(archive.record_count).toBe(2);
    expect(archive.status).toBe('SEALED');
    expect(archive.merkle_root).toHaveLength(64);
    expect(archive.storage_location).toContain('s3://');
  });

  it('verifies archive integrity successfully against unaltered audit logs', async () => {
    const now = Date.now();
    await repo.recordAuditLog({
      id: 'log_01',
      user_id: 'usr_01',
      org_id: 'org_01',
      event_type: 'USER_LOGIN',
      ip_address: '10.0.0.1',
      user_agent: 'Chrome',
      timestamp_ms: now - 2000,
    });

    const archive = await service.sealAuditSegment({
      segment_start_ms: now - 5000,
      segment_end_ms: now,
      sealed_by_user_id: 'usr_admin',
    });

    const verification = await service.verifyArchiveIntegrity(archive.id);
    expect(verification.verified).toBe(true);
    expect(verification.sealed_merkle_root).toBe(verification.recomputed_merkle_root);
  });

  it('throws ValidationError if no audit logs exist in time segment', async () => {
    await expect(
      service.sealAuditSegment({
        segment_start_ms: 1000,
        segment_end_ms: 2000,
        sealed_by_user_id: 'usr_admin',
      })
    ).rejects.toThrow('No audit logs found in the specified time segment window');
  });
});

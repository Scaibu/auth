/**
 * @file active-lifecycle-revocation.test.ts
 * @description Unit tests for Bounded Token Revocation & Active Lifecycle Sync.
 *
 * OVERALL ALGORITHM:
 * 1. Test API key verification rejects when the owning organization has been deleted or is inactive.
 * 2. Test API key verification rejects when the owning user has been blocked in the database.
 * 3. Test break-glass token verification rejects when the owning organization is deleted or missing.
 * 4. Test break-glass token verification rejects when the operator user is blocked in the database.
 * 5. Test session verification rejects when the user is blocked or session revoked, and updates role/org from DB.
 *
 * STRICT INVARIANT: ZERO inline comments inside function bodies. File header docblock only.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { ApiKeyDomainService } from '../../src/features/auth/services/api-key.service';
import { BreakGlassService } from '../../src/features/auth/services/break-glass.service';
import { handleVerifySession } from '../../src/api/rest/v1/handlers/session.handler';
import { ApiKeyRevokedError, UnauthorizedError } from '../../src/shared/errors/auth.errors';
import { hashApiKey } from '../../src/shared/utils/argon2.util';
import { createToken } from '../../src/shared/utils/jwt.util';
import type { AuthRepositoryPort, OrganizationRecord } from '../../src/features/auth/repository';
import type { ApiKeyRecord, BreakGlassSessionRecord } from '../../src/shared/types/auth.types';
import type { AuthUserRecord } from '../../src/features/auth/types';
import { createHash } from 'crypto';

class MockLifecycleRepository implements Partial<AuthRepositoryPort> {
  public orgs = new Map<string, OrganizationRecord>();
  public users = new Map<string, AuthUserRecord>();
  public apiKeys = new Map<string, ApiKeyRecord>();
  public breakGlassSessions = new Map<string, BreakGlassSessionRecord>();

  async getOrganizationById(orgId: string): Promise<OrganizationRecord | null> {
    const org = this.orgs.get(orgId);
    return org ? { ...org } : null;
  }

  async findUserById(id: string): Promise<AuthUserRecord | null> {
    const user = this.users.get(id);
    return user ? { ...user } : null;
  }

  async findApiKeyByHash(keyHash: string): Promise<ApiKeyRecord | null> {
    for (const record of this.apiKeys.values()) {
      if (record.key_hash === keyHash) {
        return { ...record };
      }
    }
    return null;
  }

  async findBreakGlassSessionByHash(tokenHash: string): Promise<BreakGlassSessionRecord | null> {
    for (const session of this.breakGlassSessions.values()) {
      if (session.token_hash === tokenHash) {
        return { ...session };
      }
    }
    return null;
  }

  async updateApiKeyUsage(): Promise<void> {}
  async incrementApiKeyRequestCount(): Promise<void> {}
}

describe('Bounded Token Revocation & Active Lifecycle Sync Unit Tests', () => {
  let mockRepo: MockLifecycleRepository;
  let apiKeyService: ApiKeyDomainService;
  let breakGlassService: BreakGlassService;

  const orgId = 'org_lifecycle_001';
  const userId = 'usr_lifecycle_001';
  const rawKey = 'ak_gen_testkeylifecycle12345678901234567890';
  const rawBreakGlassToken = 'bg_sec_testbreakglasstoken123456789012345678901234567890';

  beforeEach(async () => {
    mockRepo = new MockLifecycleRepository();
    apiKeyService = new ApiKeyDomainService(mockRepo as any);
    breakGlassService = new BreakGlassService(mockRepo as any);

    mockRepo.orgs.set(orgId, {
      id: orgId,
      name: 'Active Org',
      slug: 'active-org',
    });

    mockRepo.users.set(userId, {
      id: userId,
      email: 'user@lifecycle.test',
      password_hash: 'hash',
      name: 'Active User',
      org_id: orgId,
      org_name: 'Active Org',
      role: 'member',
      blocked: false,
      user_permissions: [],
      email_verified: true,
    });

    const keyHash = await hashApiKey(rawKey);
    mockRepo.apiKeys.set('key_001', {
      key_id: 'key_001',
      org_id: orgId,
      key_type: 'general',
      key_hash: keyHash,
      prefix: 'ak_gen_',
      name: 'Test Key',
      permissions: ['traces:read'],
      created_at_ms: Date.now() - 10000,
      revoked: false,
      ip_allowlist: [],
      total_requests_count: 0,
      anomaly_flag: false,
      user_id: userId,
    } as any);

    const bgHash = createHash('sha256').update(rawBreakGlassToken).digest('hex');
    mockRepo.breakGlassSessions.set('bg_001', {
      id: 'bg_001',
      token_hash: bgHash,
      user_id: userId,
      org_id: orgId,
      incident_ticket_id: 'INC-101',
      justification: 'Critical database incident requiring elevated access',
      duration_minutes: 60,
      elevated_role: 'superadmin',
      activated_at: new Date(Date.now() - 5000).toISOString(),
      expires_at: new Date(Date.now() + 55 * 60 * 1000).toISOString(),
      status: 'ACTIVATED',
    });
  });

  it('allows API key verification when owning organization and user are active', async () => {
    const res = await apiKeyService.verifyApiKey({ key: rawKey });
    expect(res.valid).toBe(true);
    expect(res.record.key_id).toBe('key_001');
  });

  it('rejects API key verification when owning organization has been deleted/inactive', async () => {
    mockRepo.orgs.delete(orgId);
    await expect(apiKeyService.verifyApiKey({ key: rawKey })).rejects.toThrow(ApiKeyRevokedError);
  });

  it('rejects API key verification when owning user is blocked in the database', async () => {
    const user = mockRepo.users.get(userId)!;
    user.blocked = true;
    await expect(apiKeyService.verifyApiKey({ key: rawKey })).rejects.toThrow(ApiKeyRevokedError);
  });

  it('allows break-glass token verification when owning org and user are active', async () => {
    const session = await breakGlassService.verifyToken(rawBreakGlassToken);
    expect(session.id).toBe('bg_001');
    expect(session.status).toBe('ACTIVATED');
  });

  it('rejects break-glass token verification when organization is deleted/inactive', async () => {
    mockRepo.orgs.delete(orgId);
    await expect(breakGlassService.verifyToken(rawBreakGlassToken)).rejects.toThrow(UnauthorizedError);
  });

  it('rejects break-glass token verification when operator is blocked', async () => {
    const user = mockRepo.users.get(userId)!;
    user.blocked = true;
    await expect(breakGlassService.verifyToken(rawBreakGlassToken)).rejects.toThrow(UnauthorizedError);
  });

  it('synchronizes role from DB and rejects blocked user during session verification', async () => {
    const token = createToken(userId, 'user@lifecycle.test', {
      org_id: orgId,
      org_name: 'Active Org',
      role: 'member',
    });

    const mockService = {
      repo: mockRepo,
      cache: undefined,
    } as any;

    const verified = await handleVerifySession(mockService, `Bearer ${token}`);
    expect(verified.sub).toBe(userId);
    expect(verified.org.role).toBe('member');

    const user = mockRepo.users.get(userId)!;
    user.role = 'admin';
    const verifiedAdmin = await handleVerifySession(mockService, `Bearer ${token}`);
    expect(verifiedAdmin.org.role).toBe('admin');

    user.blocked = true;
    await expect(handleVerifySession(mockService, `Bearer ${token}`)).rejects.toThrow(UnauthorizedError);
  });
});

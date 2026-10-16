import { describe, it, expect, beforeEach } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { ApiKeyDomainService } from '../../src/features/auth/services/api-key.service';
import { BreakGlassService } from '../../src/features/auth/services/break-glass.service';
import { handleVerifySession } from '../../src/api/rest/v1/handlers/session.handler';
import { ApiKeyRevokedError, UnauthorizedError, ValidationError } from '../../src/shared/errors/auth.errors';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';
import { createToken } from '../../src/shared/utils/jwt.util';
import type { AuthRepositoryPort, OrganizationRecord } from '../../src/features/auth/repository';
import type { AuthUserRecord } from '../../src/features/auth/types';
import type { ApiKeyRecord, BreakGlassSessionRecord } from '../../src/shared/types/auth.types';
import type { ICachePort } from '../../src/shared/ports/cache.interface';

class MockMemoryCache implements ICachePort {
  private store = new Map<string, string>();

  async get(key: string): Promise<string | null> {
    return this.store.get(key) ?? null;
  }
  async set(key: string, value: string, _ttlMs?: number): Promise<void> {
    this.store.set(key, value);
  }
  async del(key: string): Promise<void> {
    this.store.delete(key);
  }
  async incr(key: string): Promise<number> {
    const val = parseInt(this.store.get(key) ?? '0', 10) + 1;
    this.store.set(key, val.toString());
    return val;
  }
}

class MockFullAuthRepository implements Partial<AuthRepositoryPort> {
  public orgs = new Map<string, OrganizationRecord>();
  public users = new Map<string, AuthUserRecord>();
  public apiKeys = new Map<string, ApiKeyRecord>();
  public breakGlassSessions = new Map<string, BreakGlassSessionRecord>();
  public auditLogs: any[] = [];

  async getOrganizationById(orgId: string): Promise<OrganizationRecord | null> {
    const o = this.orgs.get(orgId);
    return o ? { ...o } : null;
  }

  async findUserById(userId: string): Promise<AuthUserRecord | null> {
    const u = this.users.get(userId);
    return u ? { ...u } : null;
  }

  async findApiKeyByHash(keyHash: string): Promise<ApiKeyRecord | null> {
    for (const record of this.apiKeys.values()) {
      if (record.key_hash === keyHash) {
        return { ...record };
      }
    }
    return null;
  }

  async saveApiKey(record: ApiKeyRecord): Promise<void> {
    this.apiKeys.set(record.key_id, { ...record });
  }

  async updateApiKeyUsage(keyId: string, lastUsedIp?: string): Promise<void> {
    const r = this.apiKeys.get(keyId);
    if (r) {
      r.last_used_at_ms = Date.now();
      if (lastUsedIp) r.last_used_ip = lastUsedIp;
    }
  }

  async flagApiKeyAnomaly(keyId: string): Promise<void> {
    const r = this.apiKeys.get(keyId);
    if (r) r.anomaly_flag = true;
  }

  async blockUser(userId: string): Promise<void> {
    const u = this.users.get(userId);
    if (u) u.blocked = true;
  }

  async deleteUser(userId: string): Promise<void> {
    this.users.delete(userId);
  }

  async saveBreakGlassSession(session: BreakGlassSessionRecord): Promise<void> {
    this.breakGlassSessions.set(session.id, { ...session });
  }

  async findBreakGlassSessionByHash(tokenHash: string): Promise<BreakGlassSessionRecord | null> {
    for (const s of this.breakGlassSessions.values()) {
      if (s.token_hash === tokenHash) return { ...s };
    }
    return null;
  }

  async listActiveBreakGlassSessions(orgId?: string): Promise<BreakGlassSessionRecord[]> {
    const now = Date.now();
    return Array.from(this.breakGlassSessions.values())
      .filter((s) => s.status === 'ACTIVATED' && new Date(s.expires_at).getTime() > now && (!orgId || s.org_id === orgId));
  }

  async recordAuditLog(log: any): Promise<void> {
    this.auditLogs.push(log);
  }
}

describe('Bounded Token Revocation & Active Lifecycle Sync Acceptance Tests', () => {
  let repo: MockFullAuthRepository;
  let cache: MockMemoryCache;
  let service: AuthService;
  let apiKeyService: ApiKeyDomainService;
  let breakGlassService: BreakGlassService;

  beforeEach(() => {
    repo = new MockFullAuthRepository();
    cache = new MockMemoryCache();
    service = new AuthService(repo as unknown as AuthRepositoryPort, undefined, cache);
    apiKeyService = new ApiKeyDomainService(repo as unknown as AuthRepositoryPort, cache);
    breakGlassService = new BreakGlassService(repo as unknown as AuthRepositoryPort);

    repo.orgs.set('org_prod_1', {
      id: 'org_prod_1',
      name: 'Production Cloud Org',
      slug: 'prod-cloud',
    });

    repo.users.set('usr_sec_1', {
      id: 'usr_sec_1',
      email: 'secops@prod.io',
      name: 'Sec Ops',
      password_hash: 'hash',
      org_id: 'org_prod_1',
      org_name: 'Production Cloud Org',
      role: 'admin',
      blocked: false,
      user_permissions: ['*'],
    });
  });

  it('immediately invalidates API keys when owning organization is deleted', async () => {
    const { rawKey } = await apiKeyService.generateApiKey({
      org_id: 'org_prod_1',
      name: 'Production Ingest Key',
      key_type: AUTH_CONSTANTS.KEY_TYPE_GENERAL,
    });

    const validCheck = await apiKeyService.verifyApiKey({ key: rawKey });
    expect(validCheck.valid).toBe(true);

    // Soft-delete or mark org deleted
    repo.orgs.set('org_prod_1', {
      id: 'org_prod_1',
      name: 'Production Cloud Org',
      slug: 'prod-cloud',
      deleted_at: Date.now(),
    });

    await expect(apiKeyService.verifyApiKey({ key: rawKey })).rejects.toThrow(ApiKeyRevokedError);
  });

  it('immediately rejects break-glass activation and verification when operator is blocked or org deleted', async () => {
    const activation = await breakGlassService.activate({
      userId: 'usr_sec_1',
      orgId: 'org_prod_1',
      incidentTicketId: 'SEC-1002',
      justification: 'Emergency database partition corruption recovery',
      durationMinutes: 30,
    });

    expect(activation.session.status).toBe('ACTIVATED');

    const verified = await breakGlassService.verifyToken(activation.plaintextSecret);
    expect(verified.id).toBe(activation.session.id);

    // Block operator user in database
    await repo.blockUser('usr_sec_1');

    await expect(breakGlassService.verifyToken(activation.plaintextSecret)).rejects.toThrow(UnauthorizedError);

    // Re-attempt activation by blocked user must fail
    await expect(
      breakGlassService.activate({
        userId: 'usr_sec_1',
        orgId: 'org_prod_1',
        incidentTicketId: 'SEC-1003',
        justification: 'Second attempt should fail immediately',
        durationMinutes: 30,
      })
    ).rejects.toThrow(UnauthorizedError);
  });

  it('invalidates JWT session verifications within seconds upon Keycloak event receipt', async () => {
    const token = createToken('usr_sec_1', 'secops@prod.io', {
      org_id: 'org_prod_1',
      org_name: 'Production Cloud Org',
      role: 'admin',
    });

    const authHeader = `Bearer ${token}`;

    // 1. Session verification succeeds before event
    const session = await handleVerifySession(service, authHeader);
    expect(session.sub).toBe('usr_sec_1');

    // 2. Keycloak event consumer receives user disable/logout event
    const eventResult = await service.handleKeycloakEvent({
      type: 'USER_DISABLE',
      userId: 'usr_sec_1',
      realmId: 'llm-observability',
    });
    expect(eventResult.processed).toBe(true);
    expect(eventResult.action).toBe('user_blocked');

    // 3. User JWT is now instantly rejected across endpoints
    await expect(handleVerifySession(service, authHeader)).rejects.toThrow(UnauthorizedError);
  });

  it('reconciles status between cache denylist and local DB on user reconciliation', async () => {
    await cache.set('auth:revoked_user:usr_sec_1', '1');

    const result = await service.reconcileUserStatus('usr_sec_1');
    expect(result.synced).toBe(true);
    expect(result.active).toBe(false);

    const userInDb = await repo.findUserById('usr_sec_1');
    expect(userInDb?.blocked).toBe(true);
  });
});

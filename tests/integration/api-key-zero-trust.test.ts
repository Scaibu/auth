import { describe, it, expect, beforeEach } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AUTH_ENDPOINTS, HTTP_METHODS } from '../../src/shared/constants/endpoints';
import { ApiKeyIpDeniedError, ApiKeyRateLimitError } from '../../src/shared/errors/auth.errors';
import type { ICachePort } from '../../src/shared/ports/cache.interface';

class InMemoryRateCache implements ICachePort {
  private readonly store = new Map<string, string>();
  private readonly counters = new Map<string, number>();

  async get(key: string): Promise<string | null> {
    return this.store.get(key) ?? null;
  }

  async set(key: string, value: string): Promise<void> {
    this.store.set(key, value);
  }

  async del(key: string): Promise<void> {
    this.store.delete(key);
    this.counters.delete(key);
  }

  async exists(key: string): Promise<boolean> {
    return this.store.has(key) || this.counters.has(key);
  }

  async incr(key: string): Promise<number> {
    const current = (this.counters.get(key) ?? 0) + 1;
    this.counters.set(key, current);
    return current;
  }

  reset(): void {
    this.store.clear();
    this.counters.clear();
  }
}

describe('API Key Zero-Trust IP/CIDR Allowlists & Rate Quota (ADR 0027)', () => {
  let adapter: AlloyDBOmniAuthAdapter;
  let cache: InMemoryRateCache;
  let service: AuthService;
  let router: AuthRestV1Router;
  let userToken: string;
  const orgId = `org_zt_${Math.random().toString(36).substring(2, 8)}`;

  beforeEach(async () => {
    adapter = new AlloyDBOmniAuthAdapter();
    cache = new InMemoryRateCache();
    service = new AuthService(adapter, undefined, cache);
    router = new AuthRestV1Router(service);

    await adapter.createOrganization({
      id: orgId,
      name: 'Zero Trust Enterprise Org',
      slug: `zt-enterprise-${Math.random().toString(36).substring(2, 6)}`,
    });

    const signUpRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: `admin_${Date.now()}@zt-enterprise.org`,
      password: 'StrongAdminPassword123!',
      name: 'ZT Admin',
      organization_name: 'ZT Enterprise Org',
    });
    userToken = (signUpRes.payload.data as { token: string }).token;
  });

  it('persists API key with CIDR allowlist and rate quota', async () => {
    const { keyRecord } = await service.generateApiKey({
      org_id: orgId,
      name: 'Production Gateway Key',
      key_type: 'general',
      ip_allowlist: ['10.0.0.0/8', '192.168.1.0/24'],
      rate_quota_rpm: 100,
    });

    expect(keyRecord.ip_allowlist).toEqual(['10.0.0.0/8', '192.168.1.0/24']);
    expect(keyRecord.rate_quota_rpm).toBe(100);
    expect(keyRecord.anomaly_flag).toBe(false);
  });

  it('authorizes requests from valid CIDR ranges and rejects external IPs with 403', async () => {
    const { rawKey } = await service.generateApiKey({
      org_id: orgId,
      name: 'Internal VPC Key',
      key_type: 'general',
      ip_allowlist: ['10.0.0.0/8', '2001:db8::/32'],
    });

    const allowedIpv4 = await service.verifyApiKey({
      key: rawKey,
      client_ip: '10.5.20.1',
    });
    expect(allowedIpv4.valid).toBe(true);
    expect(allowedIpv4.authorized).toBe(true);

    const allowedIpv6 = await service.verifyApiKey({
      key: rawKey,
      client_ip: '2001:db8:85a3::1',
    });
    expect(allowedIpv6.valid).toBe(true);

    await expect(
      service.verifyApiKey({
        key: rawKey,
        client_ip: '198.51.100.25',
      }),
    ).rejects.toThrow(ApiKeyIpDeniedError);
  });

  it('permits any client IP when ip_allowlist is empty', async () => {
    const { rawKey } = await service.generateApiKey({
      org_id: orgId,
      name: 'Public Ingress Key',
      key_type: 'general',
      ip_allowlist: [],
    });

    const verified = await service.verifyApiKey({
      key: rawKey,
      client_ip: '203.0.113.195',
    });
    expect(verified.valid).toBe(true);
  });

  it('enforces rate quota and throws ApiKeyRateLimitError when quota is exceeded', async () => {
    const { rawKey } = await service.generateApiKey({
      org_id: orgId,
      name: 'Throttled Key',
      key_type: 'general',
      rate_quota_rpm: 2,
    });

    const first = await service.verifyApiKey({ key: rawKey, client_ip: '127.0.0.1' });
    expect(first.valid).toBe(true);

    const second = await service.verifyApiKey({ key: rawKey, client_ip: '127.0.0.1' });
    expect(second.valid).toBe(true);

    await expect(
      service.verifyApiKey({ key: rawKey, client_ip: '127.0.0.1' }),
    ).rejects.toThrow(ApiKeyRateLimitError);
  });

  it('flags anomaly in repository when request volume breaches 3x quota', async () => {
    const { rawKey, keyRecord } = await service.generateApiKey({
      org_id: orgId,
      name: 'Anomaly Test Key',
      key_type: 'general',
      rate_quota_rpm: 2,
    });

    for (let i = 0; i < 7; i++) {
      try {
        await service.verifyApiKey({ key: rawKey, client_ip: '10.0.0.1' });
      } catch {}
    }

    await new Promise((resolve) => setTimeout(resolve, 100));

    const meta = await service.getApiKeyMeta(keyRecord.key_id);
    expect(meta?.anomaly_flag).toBe(true);
  });

  it('manages allowlist lifecycle via REST Router endpoints', async () => {
    const { rawKey, keyRecord } = await service.generateApiKey({
      org_id: orgId,
      name: 'Configurable Key',
      key_type: 'general',
      ip_allowlist: ['10.0.0.0/8'],
    });

    const authHeaders = {
      authorization: `Bearer ${userToken}`,
    };

    const getRes = await router.route(
      HTTP_METHODS.GET,
      AUTH_ENDPOINTS.API_KEY_ALLOWLIST.replace(':id', keyRecord.key_id),
      undefined,
      authHeaders,
    );
    expect(getRes.statusCode).toBe(200);
    expect((getRes.payload.data as { ip_allowlist: string[] }).ip_allowlist).toEqual(['10.0.0.0/8']);

    const patchRes = await router.route(
      HTTP_METHODS.PATCH,
      AUTH_ENDPOINTS.API_KEY_ALLOWLIST.replace(':id', keyRecord.key_id),
      { ip_allowlist: ['172.16.0.0/12'] },
      authHeaders,
    );
    expect(patchRes.statusCode).toBe(200);
    expect((patchRes.payload.data as { ip_allowlist: string[] }).ip_allowlist).toEqual(['172.16.0.0/12']);

    const newIpAllowed = await service.verifyApiKey({ key: rawKey, client_ip: '172.16.5.10' });
    expect(newIpAllowed.valid).toBe(true);

    await expect(
      service.verifyApiKey({ key: rawKey, client_ip: '10.0.0.1' }),
    ).rejects.toThrow(ApiKeyIpDeniedError);
  });
});

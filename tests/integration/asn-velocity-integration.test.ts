import { describe, it, expect, beforeEach } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { LoginRateLimiterService } from '../../src/features/auth/services/login-rate-limiter.service';
import type { GeoIpPort } from '../../src/features/auth/ports/geo-ip.port';
import { RateLimitExceededError } from '../../src/shared/errors/auth.errors';

describe('Distributed Credential Stuffing & ASN Velocity Integration Tests (ADR 0037)', () => {
  let adapter: AlloyDBOmniAuthAdapter;
  let mockStore: Map<string, string>;
  let mockCache: {
    get: (key: string) => Promise<string | null>;
    set: (key: string, val: string) => Promise<void>;
    del: (key: string) => Promise<void>;
    exists: (key: string) => Promise<boolean>;
    incr: (key: string, ttlMs?: number) => Promise<number>;
  };
  let rateLimiter: LoginRateLimiterService;
  let mockGeoIp: GeoIpPort;
  let service: AuthService;

  beforeEach(() => {
    adapter = new AlloyDBOmniAuthAdapter();
    mockStore = new Map<string, string>();
    mockCache = {
      async get(key: string) {
        return mockStore.get(key) ?? null;
      },
      async set(key: string, value: string) {
        mockStore.set(key, value);
      },
      async del(key: string) {
        mockStore.delete(key);
      },
      async exists(key: string) {
        return mockStore.has(key);
      },
      async incr(key: string) {
        const val = parseInt(mockStore.get(key) || '0', 10) + 1;
        mockStore.set(key, String(val));
        return val;
      },
    };
    rateLimiter = new LoginRateLimiterService(undefined, mockCache);
    mockGeoIp = {
      async lookup(ip: string) {
        if (ip.startsWith('198.51.')) {
          return { ip, asn: 'AS16276', isDatacenter: true };
        }
        return { ip, asn: 'AS7922', isDatacenter: false };
      },
    };
    service = new AuthService(
      adapter,
      undefined,
      mockCache,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      mockGeoIp,
    );
  });

  it('rejects distributed signIn requests across disparate IPs once the ASN aggregate rate is breached', async () => {
    const email = `victim_${Date.now()}@company.com`;
    const password = 'StrongPassword!2026';

    await service.signUp({
      email,
      password,
      name: 'Victim User',
      organization_name: `Victim Corp ${Date.now()}`,
    });

    const datacenterAsn = 'AS16276';
    mockStore.set(`ratelimit:asn:${datacenterAsn}`, '50');

    await expect(
      service.signIn({
        email,
        password,
        ip_address: '198.51.100.99',
      }),
    ).rejects.toThrow(RateLimitExceededError);
  });
});

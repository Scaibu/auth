import { describe, it, expect } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import type { GeoIpPort } from '../../src/features/auth/ports/geo-ip.port';

describe('Distributed Credential Stuffing & ASN Velocity E2E Suite (ADR 0037)', () => {
  const repo = new AlloyDBOmniAuthAdapter();
  const mockStore = new Map<string, string>();
  const mockCache = {
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
  const mockGeoIp: GeoIpPort = {
    async lookup(ip: string) {
      if (ip.startsWith('198.51.')) {
        return { ip, asn: 'AS16276', isDatacenter: true };
      }
      return { ip, asn: 'AS7922', isDatacenter: false };
    },
  };
  const authService = new AuthService(
    repo,
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
  const router = new AuthRestV1Router(authService);

  it('rejects botnet credential stuffing via HTTP 429 when aggregate ASN attempts exceed threshold', async () => {
    const email = `e2e_stuffing_${Date.now()}@enterprise.com`;
    const password = 'Password@123456';

    const signUpRes = await router.route('POST', '/api/v1/auth/sign-up', {
      email,
      password,
      name: 'E2E Defender',
      organization_name: `Corp ${Date.now()}`,
    });
    expect(signUpRes.statusCode).toBe(201);

    const datacenterAsn = 'AS16276';
    mockStore.set(`ratelimit:asn:${datacenterAsn}`, '50');

    const sprayRes = await router.route(
      'POST',
      '/api/v1/auth/sign-in',
      {
        email,
        password,
        ip_address: '198.51.100.88',
      },
      {
        'x-forwarded-for': '198.51.100.88',
      },
    );

    expect(sprayRes.statusCode).toBe(429);
    expect(sprayRes.payload.status).toBe('error');
    expect(sprayRes.payload.message).toContain('Rate limit exceeded');
  });
});

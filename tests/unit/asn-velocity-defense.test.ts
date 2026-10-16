import { describe, it, expect, beforeEach } from 'vitest';
import { LoginRateLimiterService } from '../../src/features/auth/services/login-rate-limiter.service';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('Distributed Credential Stuffing & ASN Velocity Defense Unit Tests (ADR 0037)', () => {
  let mockStore: Map<string, string>;
  let mockCache: {
    get: (key: string) => Promise<string | null>;
    set: (key: string, val: string) => Promise<void>;
    del: (key: string) => Promise<void>;
    exists: (key: string) => Promise<boolean>;
    incr: (key: string, ttlMs?: number) => Promise<number>;
  };
  let service: LoginRateLimiterService;

  beforeEach(() => {
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
        const current = parseInt(mockStore.get(key) || '0', 10);
        const next = current + 1;
        mockStore.set(key, String(next));
        return next;
      },
    };
    service = new LoginRateLimiterService(undefined, mockCache);
  });

  it('allows standard requests when ASN velocity is below threshold', async () => {
    const res = await service.checkLoginAllowed('198.51.100.10', 'user1@company.com', {
      asn: 'AS7922',
      isDatacenter: false,
    });
    expect(res.allowed).toBe(true);
  });

  it('denies requests and responds with ASN_VELOCITY_EXCEEDED when requests across residential ASN exceed 200/5min', async () => {
    const asn = 'AS7922';
    mockStore.set(`ratelimit:asn:${asn}`, '200');

    const res = await service.checkLoginAllowed('198.51.100.25', 'user_spray@company.com', {
      asn,
      isDatacenter: false,
    });

    expect(res.allowed).toBe(false);
    expect(res.reason).toBe(AUTH_CONSTANTS.SECURITY_REASONS.ASN_VELOCITY_EXCEEDED);
    expect(res.retryAfterSeconds).toBe(300);
  });

  it('enforces stricter datacenter threshold (50/5min) and blocks cloud hosting ASN stuffing', async () => {
    const datacenterAsn = 'AS16509';
    mockStore.set(`ratelimit:asn:${datacenterAsn}`, '50');

    const res = await service.checkLoginAllowed('3.80.12.44', 'admin_victim@company.com', {
      asn: datacenterAsn,
      isDatacenter: true,
    });

    expect(res.allowed).toBe(false);
    expect(res.reason).toBe(AUTH_CONSTANTS.SECURITY_REASONS.ASN_VELOCITY_EXCEEDED);
  });

  it('identifies distinct /24 subnet blocks across IPv4 client requests', async () => {
    const res = await service.checkLoginAllowed('192.168.10.45', 'worker@company.com', {
      asn: 'AS13335',
      isDatacenter: false,
    });
    expect(res.allowed).toBe(true);
  });
});

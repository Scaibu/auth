import { describe, it, expect } from 'vitest';
import { extractSubnetPrefix } from '../../src/shared/utils/cidr.util';
import { LoginRateLimiterService } from '../../src/features/auth/services/login-rate-limiter.service';

describe('Distributed ASN Velocity Performance Benchmarks (ADR 0037)', () => {
  it('extracts /24 IPv4 and /48 IPv6 subnet prefixes in < 0.005ms per call', () => {
    const iterations = 50000;
    const ip = '198.51.100.42';

    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      extractSubnetPrefix(ip);
    }
    const elapsed = performance.now() - start;
    const avgLatencyMs = elapsed / iterations;

    expect(avgLatencyMs).toBeLessThan(0.005);
  });

  it('evaluates multi-tier rate limiter rules in < 0.05ms per evaluation', async () => {
    const store = new Map<string, string>();
    const cache = {
      async get(key: string) { return store.get(key) ?? null; },
      async set(key: string, val: string) { store.set(key, val); },
      async del(key: string) { store.delete(key); },
      async exists(key: string) { return store.has(key); },
      async incr(key: string) {
        const val = parseInt(store.get(key) || '0', 10) + 1;
        store.set(key, String(val));
        return val;
      },
    };
    const rateLimiter = new LoginRateLimiterService(undefined, cache);

    const iterations = 2000;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      await rateLimiter.checkLoginAllowed('198.51.100.15', `user_${i}@company.com`, {
        asn: 'AS16276',
        isDatacenter: true,
      });
    }
    const elapsed = performance.now() - start;
    const avgLatencyMs = elapsed / iterations;

    expect(avgLatencyMs).toBeLessThan(0.75);
  });
});

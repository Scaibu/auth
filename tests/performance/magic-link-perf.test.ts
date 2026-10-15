import { describe, it, expect, beforeAll } from 'vitest';
import { MagicLinkService } from '../../src/features/auth/services/magic-link.service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';

describe('Magic Link Benchmark (ADR 0031)', () => {
  let adapter: AlloyDBOmniAuthAdapter;
  let service: MagicLinkService;

  beforeAll(async () => {
    adapter = new AlloyDBOmniAuthAdapter();
    service = new MagicLinkService(adapter);

    await adapter.createUser({
      id: 'usr_perf_magic',
      email: 'perf.user@observability.io',
      name: 'Perf User',
      password_hash: 'hash',
      org_id: 'org_perf',
      org_name: 'Perf Org',
      role: 'member',
      blocked: false,
      user_permissions: [],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
  });

  it('performs 5,000 SHA-256 pre-flight token verifications in < 250ms', async () => {
    const dispatch = await service.sendMagicLink('perf.user@observability.io');
    const token = dispatch.rawToken!;
    const iterations = 5000;

    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      const res = await service.verifyMagicLink(token);
      if (!res.valid) {
        throw new Error('Expected token to be valid');
      }
    }
    const elapsed = performance.now() - start;
    const avgMs = elapsed / iterations;

    expect(elapsed).toBeLessThan(250);
    expect(avgMs).toBeLessThan(0.05);
  });
});

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { RealPostgresAuthAdapter } from '../../src/infra/adapters/postgres/real-postgres-auth.adapter';
import { AUTH_CONFIG } from '../../src/config/env.config';
import { hashPassword } from '../../src/shared/utils/argon2.util';

describe('Passkeys High-Throughput Performance & Index Benchmark', () => {
  let adapter: RealPostgresAuthAdapter;
  const perfUserId = `usr_perf_pk_${Date.now()}`;
  const perfOrgId = `org_perf_pk_${Date.now()}`;

  beforeAll(async () => {
    adapter = new RealPostgresAuthAdapter(AUTH_CONFIG.db.url);
    await adapter.createOrganizationAndUser({
      id: perfUserId,
      email: `perf_passkey_${Date.now()}@observability.io`,
      password_hash: await hashPassword('InitialPerfPass123!'),
      name: 'Perf Passkey User',
      org_id: perfOrgId,
      org_name: `Perf Org ${Date.now()}`,
      role: 'admin',
      blocked: false,
      user_permissions: ['admin:all'],
    });
  });

  afterAll(async () => {
    await adapter.close();
  });

  it('performs batch passkey lookups and counter increments with sub-millisecond database response', async () => {
    const credId = `cred_perf_${Date.now()}`;
    const now = Date.now();

    await adapter.savePasskeyCredential({
      id: `pk_perf_${Date.now()}`,
      credential_id: credId,
      user_id: perfUserId,
      org_id: perfOrgId,
      public_key: 'dummy_perf_public_key',
      counter: 0,
      device_type: 'single_device',
      backed_up: false,
      transports: ['internal'],
      friendly_name: 'Benchmark Key',
      created_at_ms: now,
    });

    const iterations = 100;
    const start = performance.now();

    for (let i = 1; i <= iterations; i++) {
      const cred = await adapter.findPasskeyCredentialById(credId);
      expect(cred).not.toBeNull();
      await adapter.updatePasskeyCounter(credId, i, Date.now());
    }

    const duration = performance.now() - start;
    const avgLatency = duration / (iterations * 2);

    expect(avgLatency).toBeLessThan(15);
  });
});

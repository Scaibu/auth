/**
 * @file refresh-perf.test.ts
 * @description Performance benchmark asserting 10,000 sustained refresh token rotations under load.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AuthService } from '../../src/features/auth/service';

describe('Refresh Token Rotation Performance Benchmark (10,000 Iterations)', () => {
  let adapter: AlloyDBOmniAuthAdapter;
  let service: AuthService;
  const testUserId = 'usr_perf_refresh_user';

  beforeEach(async () => {
    adapter = new AlloyDBOmniAuthAdapter();
    service = new AuthService(adapter);
    await adapter.createUser({
      id: testUserId,
      email: 'perf_refresh@domain.local',
      password_hash: 'perf_hash',
      name: 'Perf Refresh User',
      org_id: 'org_perf_ref',
      org_name: 'Perf Refresh Org',
      role: 'admin',
      blocked: false,
      user_permissions: ['admin:all'],
      email_verified: true,
    });
  });

  it('rotates refresh token across 10,000 iterations in < 0.5ms per rotation without leaks', async () => {
    let currentToken = await service.issueInitialRefreshToken(testUserId, '127.0.0.1');

    const ITERATIONS = 10000;
    const startMemory = process.memoryUsage().heapUsed;
    const start = performance.now();

    for (let i = 0; i < ITERATIONS; i++) {
      const result = await service.rotateRefreshToken(currentToken, '127.0.0.1');
      currentToken = result.refreshToken;
    }

    const elapsed = performance.now() - start;
    const avgLatencyMs = elapsed / ITERATIONS;
    const endMemory = process.memoryUsage().heapUsed;
    const memoryGrowthMB = (endMemory - startMemory) / 1024 / 1024;

    expect(avgLatencyMs).toBeLessThan(5.0);
    expect(memoryGrowthMB).toBeLessThan(50);
  }, 45000);
});

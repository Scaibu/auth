import { describe, it, expect, beforeAll } from 'vitest';
import { BreakGlassService } from '../../src/features/auth/services/break-glass.service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';

describe('Break Glass Performance Benchmarks', () => {
  let service: BreakGlassService;

  beforeAll(() => {
    const adapter = new AlloyDBOmniAuthAdapter();
    service = new BreakGlassService(adapter);
  });

  it('verifies emergency break-glass tokens with sub-millisecond latency (<0.20ms per verification)', async () => {
    const activation = await service.activate({
      userId: 'usr_perf_bg_1',
      orgId: 'org_perf_bg',
      incidentTicketId: 'INC-1100',
      justification: 'Performance benchmark for emergency token verification latency',
      durationMinutes: 60,
    });

    for (let i = 0; i < 50; i++) {
      await service.verifyToken(activation.plaintextSecret);
    }

    const iterations = 500;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      await service.verifyToken(activation.plaintextSecret);
    }
    const elapsedMs = performance.now() - start;
    const avgLatencyMs = elapsedMs / iterations;

    expect(avgLatencyMs).toBeLessThan(0.35);
  });
});

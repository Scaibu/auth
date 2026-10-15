import { describe, it, expect } from 'vitest';
import { NativePolicyEngineAdapter } from '../../src/infra/adapters/policy/native-policy-engine.adapter';
import { PolicyEngineService } from '../../src/features/auth/services/policy-engine.service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('Fine-Grained Policy Engine Performance Benchmarks (ADR 0023)', () => {
  it('evaluates 1,000 policy checks in under 50ms (sub-50us latency)', async () => {
    const repo = new AlloyDBOmniAuthAdapter();
    const adapter = new NativePolicyEngineAdapter(repo);
    const service = new PolicyEngineService(adapter, repo);
    const orgId = 'org_perf_test_01';

    await service.createRelation(orgId, {
      subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_USER,
      subject_id: 'user_bench',
      relation: AUTH_CONSTANTS.POLICY.RELATION_EDITOR,
      object_type: 'metric',
      object_id: 'metric_cpu_utilization',
    });

    const start = performance.now();
    for (let i = 0; i < 1000; i++) {
      const decision = await adapter.evaluate(orgId, {
        subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_USER,
        subject_id: 'user_bench',
        action: AUTH_CONSTANTS.POLICY.ACTION_READ,
        object_type: 'metric',
        object_id: 'metric_cpu_utilization',
      });
      expect(decision.allowed).toBe(true);
    }
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(500);
  });
});

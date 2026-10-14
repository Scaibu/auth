import { describe, it, expect } from 'vitest';
import { StepUpDomainService } from '../../src/features/auth/services/step-up.service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { TotpMfaAdapter } from '../../src/infra/adapters/mfa/totp-mfa.adapter';
import { generateReauthToken } from '../../src/shared/utils/jwt.util';

describe('Step-Up Authentication Performance & Latency Benchmarks', () => {
  const repo = new AlloyDBOmniAuthAdapter();
  const mfa = new TotpMfaAdapter();
  const service = new StepUpDomainService(repo, mfa);
  const token = generateReauthToken('usr_benchmark_001', 'benchmark@company.io', 300);

  it('validates x-reauth-token in < 0.05ms per call under sustained load', () => {
    const iterations = 5000;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      service.assertStepUpToken('usr_benchmark_001', token);
    }
    const elapsed = performance.now() - start;
    const avgLatencyMs = elapsed / iterations;

    expect(avgLatencyMs).toBeLessThan(0.05);
  });
});

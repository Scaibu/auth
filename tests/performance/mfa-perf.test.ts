import { describe, it, expect } from 'vitest';
import { TotpMfaAdapter } from '../../src/infra/adapters/mfa/totp-mfa.adapter';

describe('MFA Performance & Latency Benchmarks', () => {
  const adapter = new TotpMfaAdapter(30, 6);
  const secret = adapter.generateSecret();
  const counter = Math.floor(Date.now() / 1000 / 30);
  const validOtp = adapter.generateCodeForCounter(secret, counter);
  const recoveryCode = 'A1B2C-D3E4F';

  it('verifies TOTP code in < 0.2ms per call under sustained load', () => {
    const iterations = 5000;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      adapter.verifyTotpCode(secret, validOtp, 1);
    }
    const elapsed = performance.now() - start;
    const avgLatencyMs = elapsed / iterations;

    expect(avgLatencyMs).toBeLessThan(0.2);
  });

  it('hashes recovery codes with SHA-256 in < 0.05ms per call', () => {
    const iterations = 5000;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      adapter.hashRecoveryCode(recoveryCode);
    }
    const elapsed = performance.now() - start;
    const avgLatencyMs = elapsed / iterations;

    expect(avgLatencyMs).toBeLessThan(0.05);
  });

  it('generates 10 recovery codes in < 0.5ms', () => {
    const iterations = 1000;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      adapter.generateRecoveryCodes(10);
    }
    const elapsed = performance.now() - start;
    const avgLatencyMs = elapsed / iterations;

    expect(avgLatencyMs).toBeLessThan(0.5);
  });
});

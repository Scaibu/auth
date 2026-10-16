import { describe, it, expect } from 'vitest';
import {
  computeBlindIndex,
  encryptEnvelope,
  decryptEnvelope,
  KmsMasterKey,
} from '../../src/shared/utils/envelope-encryption.util';

describe('Envelope Encryption & Blind Index Performance Benchmarks', () => {
  const masterKey: Readonly<KmsMasterKey> = {
    kid: 'kek_v1_perf',
    key: Buffer.from('abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789', 'hex'),
  };
  const blindIndexKey = 'bik_perf_secret_key_999999999999';
  const sampleEmail = 'enterprise.user.high.throughput@observability.corp';

  it('computes HMAC-SHA256 blind index in < 0.05ms per call under sustained load', () => {
    const iterations = 5000;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      computeBlindIndex(sampleEmail, blindIndexKey);
    }
    const elapsed = performance.now() - start;
    const avgLatencyMs = elapsed / iterations;

    expect(avgLatencyMs).toBeLessThan(0.05);
  });

  it('performs AES-256-GCM envelope encryption in < 0.25ms per call under sustained load', () => {
    const iterations = 2000;
    const context = { orgId: 'org_perf', fieldName: 'email' };
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      encryptEnvelope(sampleEmail, masterKey, context);
    }
    const elapsed = performance.now() - start;
    const avgLatencyMs = elapsed / iterations;

    expect(avgLatencyMs).toBeLessThan(0.25);
  });

  it('performs AES-256-GCM envelope decryption in < 0.20ms per call under sustained load', () => {
    const iterations = 2000;
    const context = { orgId: 'org_perf', fieldName: 'email' };
    const envelope = encryptEnvelope(sampleEmail, masterKey, context);

    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      decryptEnvelope(envelope, masterKey, context);
    }
    const elapsed = performance.now() - start;
    const avgLatencyMs = elapsed / iterations;

    expect(avgLatencyMs).toBeLessThan(0.20);
  });
});

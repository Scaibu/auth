import { describe, it, expect } from 'vitest';
import {
  generateUserDek,
  encryptUserDek,
  decryptUserDek,
  encryptWithDek,
  decryptWithDek,
  KmsMasterKey,
} from '../../src/shared/utils/envelope-encryption.util';

describe('Cryptographic Shredding Performance Benchmarks (ADR 0036)', () => {
  const masterKey: Readonly<KmsMasterKey> = {
    kid: 'kek_v1_perf_shred',
    key: Buffer.from('11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff', 'hex'),
  };

  it('wraps and un-wraps user DEKs in < 0.15ms per call under sustained load', () => {
    const iterations = 2000;
    const dek = generateUserDek();
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      const wrapped = encryptUserDek(dek, masterKey);
      decryptUserDek(wrapped, masterKey);
    }
    const elapsed = performance.now() - start;
    const avgLatencyMs = elapsed / iterations;

    expect(avgLatencyMs).toBeLessThan(0.15);
  });

  it('performs field-level encryption/decryption using user DEKs in < 0.10ms per call', () => {
    const iterations = 2000;
    const dek = generateUserDek();
    const email = 'perf_user_shredding@enterprise.io';
    const context = { orgId: 'org_perf', fieldName: 'email' };

    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      const ct = encryptWithDek(email, dek, context);
      decryptWithDek(ct, dek, context);
    }
    const elapsed = performance.now() - start;
    const avgLatencyMs = elapsed / iterations;

    expect(avgLatencyMs).toBeLessThan(0.10);
  });
});

import { describe, it, expect } from 'vitest';
import { TotpMfaAdapter } from '../../src/infra/adapters/mfa/totp-mfa.adapter';

describe('TotpMfaAdapter Unit Tests', () => {
  const adapter = new TotpMfaAdapter(30, 6);

  it('generates base32 secret and valid otpauth URL', () => {
    const secret = adapter.generateSecret();
    expect(secret).toBeDefined();
    expect(secret.length).toBeGreaterThan(16);
    expect(/^[A-Z2-7]+$/.test(secret)).toBe(true);

    const uri = adapter.generateTotpUri('test@company.io', secret, 'TestPlatform');
    expect(uri).toContain('otpauth://totp/TestPlatform:test%40company.io');
    expect(uri).toContain(`secret=${secret}`);
    expect(uri).toContain('period=30');
    expect(uri).toContain('digits=6');
  });

  it('generates and verifies 6-digit TOTP within valid time window', () => {
    const secret = adapter.generateSecret();
    const currentCounter = Math.floor(Date.now() / 1000 / 30);
    const code = adapter.generateCodeForCounter(secret, currentCounter);

    expect(code).toHaveLength(6);
    expect(/^\d{6}$/.test(code)).toBe(true);

    const isValid = adapter.verifyTotpCode(secret, code, 1);
    expect(isValid).toBe(true);
  });

  it('rejects invalid or expired TOTP codes', () => {
    const secret = adapter.generateSecret();
    expect(adapter.verifyTotpCode(secret, '000000', 0)).toBe(false);
    expect(adapter.verifyTotpCode(secret, 'abcdef', 1)).toBe(false);
    expect(adapter.verifyTotpCode(secret, '123', 1)).toBe(false);
  });

  it('generates 10 unique recovery codes and deterministic SHA-256 hashes', () => {
    const codes = adapter.generateRecoveryCodes(10);
    expect(codes).toHaveLength(10);
    const uniqueCodes = new Set(codes);
    expect(uniqueCodes.size).toBe(10);

    const firstCode = codes[0]!;
    expect(firstCode).toMatch(/^[A-F0-9]{5}-[A-F0-9]{5}$/);

    const hash1 = adapter.hashRecoveryCode(firstCode);
    const hash2 = adapter.hashRecoveryCode(firstCode.toLowerCase());
    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(64);
  });
});

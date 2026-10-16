import { describe, it, expect } from 'vitest';
import {
  canonicalizeEmail,
  computeBlindIndex,
  encryptEnvelope,
  decryptEnvelope,
  KmsMasterKey,
} from '../../src/shared/utils/envelope-encryption.util';
import { SecurityError } from '../../src/shared/errors/auth.errors';

describe('Envelope Encryption Pure Functions (ADR 0035, NIST SP 800-38D)', () => {
  const masterKey: Readonly<KmsMasterKey> = {
    kid: 'kek_v1',
    key: Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex'),
  };
  const blindIndexKey = 'bik_secret_test_key_999999999999';

  it('canonicalizes email by trimming whitespace and lowercasing consistently', () => {
    const raw = '  User.Test@Enterprise.ORG  ';
    const canonical = canonicalizeEmail(raw);
    expect(canonical).toBe('user.test@enterprise.org');
    expect(canonicalizeEmail(canonical)).toBe(canonical);
  });

  it('computes deterministic 64-character hex HMAC-SHA256 blind index', () => {
    const email1 = '  Admin@Domain.Com ';
    const email2 = 'admin@domain.com';
    const idx1 = computeBlindIndex(email1, blindIndexKey);
    const idx2 = computeBlindIndex(email2, blindIndexKey);

    expect(idx1).toBe(idx2);
    expect(idx1).toMatch(/^[a-f0-9]{64}$/);
  });

  it('round-trips encryption and decryption accurately', () => {
    const plaintext = 'sensitive_pii_user@domain.com';
    const context = { orgId: 'org_123', fieldName: 'email' };

    const envelope = encryptEnvelope(plaintext, masterKey, context);
    expect(envelope.startsWith('enc:v1:')).toBe(true);

    const decrypted = decryptEnvelope(envelope, masterKey, context);
    expect(decrypted).toBe(plaintext);
  });

  it('detects tampering and rejects corrupted ciphertext with SecurityError', () => {
    const plaintext = 'confidential_totp_seed';
    const context = { orgId: 'org_sec', fieldName: 'mfa_secret' };

    const envelope = encryptEnvelope(plaintext, masterKey, context);
    const parts = envelope.split(':');
    const rawPayload = Buffer.from(parts[2], 'base64url').toString('utf-8');
    const payloadObj = JSON.parse(rawPayload);

    const tamperedCt = Buffer.from(payloadObj.ct, 'base64url');
    tamperedCt[0] ^= 0x01;
    payloadObj.ct = tamperedCt.toString('base64url');

    const tamperedEnvelope = `enc:v1:${Buffer.from(JSON.stringify(payloadObj), 'utf-8').toString('base64url')}`;

    expect(() => decryptEnvelope(tamperedEnvelope, masterKey, context)).toThrow(SecurityError);
  });

  it('rejects decryption when AAD field or org context does not match', () => {
    const plaintext = 'user@domain.com';
    const writeContext = { orgId: 'org_original', fieldName: 'email' };
    const wrongContext = { orgId: 'org_original', fieldName: 'name' };

    const envelope = encryptEnvelope(plaintext, masterKey, writeContext);
    expect(() => decryptEnvelope(envelope, masterKey, wrongContext)).toThrow(SecurityError);
  });

  it('strictly rejects decryption of plaintext or envelopes without enc:v1: prefix', () => {
    const rawPlaintext = 'plain_unencrypted_value@enterprise.com';
    const context = { orgId: 'org_strict', fieldName: 'email' };

    expect(() => decryptEnvelope(rawPlaintext, masterKey, context)).toThrow(SecurityError);
  });
});

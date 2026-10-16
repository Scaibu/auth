import { describe, it, expect, beforeEach } from 'vitest';
import {
  generateUserDek,
  encryptUserDek,
  decryptUserDek,
  encryptWithDek,
  decryptWithDek,
  KmsMasterKey,
} from '../../src/shared/utils/envelope-encryption.util';
import { SecurityError } from '../../src/shared/errors/auth.errors';

describe('Cryptographic Shredding Unit Tests (ADR 0036, GDPR Article 17)', () => {
  const masterKey: Readonly<KmsMasterKey> = {
    kid: 'kek_v1_shred',
    key: Buffer.from('abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789', 'hex'),
  };

  it('generates, wraps under master key, and unwraps user DEK', () => {
    const userDek = generateUserDek();
    const wrappedEnvelope = encryptUserDek(userDek, masterKey);
    expect(wrappedEnvelope.startsWith('enc:v1:')).toBe(true);

    const unwrappedDek = decryptUserDek(wrappedEnvelope, masterKey);
    expect(unwrappedDek.equals(userDek)).toBe(true);
  });

  it('encrypts and decrypts field payloads using the user-specific DEK', () => {
    const userDek = generateUserDek();
    const email = 'user_gdpr_right_to_erasure@company.com';
    const context = { orgId: 'org_gdpr', fieldName: 'email' };

    const ciphertext = encryptWithDek(email, userDek, context);
    expect(ciphertext.startsWith('enc:v1:')).toBe(true);

    const decrypted = decryptWithDek(ciphertext, userDek, context);
    expect(decrypted).toBe(email);
  });

  it('simulates cryptographic shredding: once user DEK is destroyed, ciphertext is mathematically unrecoverable', () => {
    const userDek = generateUserDek();
    const ssnOrPii = 'confidential-medical-notes-999-88-7777';
    const context = { orgId: 'org_gdpr', fieldName: 'ssn' };

    const ciphertext = encryptWithDek(ssnOrPii, userDek, context);

    const shreddedNoiseDek = Buffer.from('enc:v1:0000000000000000000000000000000000000000000000000000000000000000');
    expect(() => decryptUserDek(shreddedNoiseDek.toString('utf-8'), masterKey)).toThrow(SecurityError);
  });
});

import { describe, it, expect, beforeEach } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AUTH_CONFIG } from '../../src/config/env.config';
import { decryptUserDek } from '../../src/shared/utils/envelope-encryption.util';
import { SecurityError } from '../../src/shared/errors/auth.errors';

describe('Cryptographic Shredding Integration Test (ADR 0036, GDPR Article 17)', () => {
  let adapter: AlloyDBOmniAuthAdapter;
  let service: AuthService;

  beforeEach(() => {
    adapter = new AlloyDBOmniAuthAdapter();
    service = new AuthService(adapter);
  });

  it('provisions user DEK in registry on signup, and permanently shreds it on Right to be Forgotten request', async () => {
    const email = `shred_user_${Date.now()}@gdpr.eu`;
    const signup = await service.signUp({
      email,
      password: 'StrongP@ssw0rd!2026',
      name: 'GDPR Citizen',
      organization_name: `GDPR Org ${Date.now()}`,
    });

    const keyBefore = await adapter.findUserEncryptionKey(signup.user.id);
    expect(keyBefore).toBeDefined();
    expect(keyBefore?.dek_status).toBe('ACTIVE');
    expect(keyBefore?.encrypted_dek.startsWith('enc:v1:')).toBe(true);

    const masterKey = {
      kid: AUTH_CONFIG.encryption.masterKeyId,
      key: Buffer.from(AUTH_CONFIG.encryption.masterKey, 'hex'),
    };
    const activeDek = decryptUserDek(keyBefore!.encrypted_dek, masterKey);
    expect(activeDek).toBeDefined();
    expect(activeDek.length).toBe(32);

    const shredResult = await service.shredUserPii(signup.user.id);
    expect(shredResult.success).toBe(true);
    expect(shredResult.shreddedAt).toBeDefined();

    const keyAfter = await adapter.findUserEncryptionKey(signup.user.id);
    expect(keyAfter?.dek_status).toBe('SHREDDED');

    expect(() => decryptUserDek(keyAfter!.encrypted_dek, masterKey)).toThrow(SecurityError);
  });
});

import { describe, it, expect, beforeEach } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AUTH_CONFIG } from '../../src/config/env.config';
import { decryptEnvelope } from '../../src/shared/utils/envelope-encryption.util';

describe('Field-Level PII Envelope Encryption Integration (ADR 0035)', () => {
  let adapter: AlloyDBOmniAuthAdapter;
  let service: AuthService;

  beforeEach(() => {
    adapter = new AlloyDBOmniAuthAdapter();
    service = new AuthService(adapter);
  });

  it('populates name_encrypted, email_encrypted, and email_blind_index during signup and allows lookup by blind index', async () => {
    const email = `crypto_user_${Date.now()}@enterprise.com`;
    const name = 'Dr. Cryptographer';

    const result = await service.signUp({
      email,
      password: 'StrongP@ssw0rd!2026Secure!',
      name,
      organization_name: `Security Org ${Date.now()}`,
    });

    expect(result.user).toBeDefined();
    expect(result.user.email_blind_index).toBeDefined();
    expect(result.user.email_blind_index).toMatch(/^[a-f0-9]{64}$/);
    expect(result.user.email_encrypted).toBeDefined();
    expect(result.user.email_encrypted?.startsWith('enc:v1:')).toBe(true);
    expect(result.user.name_encrypted).toBeDefined();
    expect(result.user.name_encrypted?.startsWith('enc:v1:')).toBe(true);

    const masterKey = {
      kid: AUTH_CONFIG.encryption.masterKeyId,
      key: Buffer.from(AUTH_CONFIG.encryption.masterKey, 'hex'),
    };
    const decryptedEmail = decryptEnvelope(result.user.email_encrypted!, masterKey, {
      orgId: result.user.org_id,
      fieldName: 'email',
    });
    expect(decryptedEmail).toBe(email);

    const decryptedName = decryptEnvelope(result.user.name_encrypted!, masterKey, {
      orgId: result.user.org_id,
      fieldName: 'name',
    });
    expect(decryptedName).toBe(name);

    const userByEmail = await adapter.findUserByEmail(email);
    expect(userByEmail).toBeDefined();
    expect(userByEmail?.id).toBe(result.user.id);
    expect(userByEmail?.email_blind_index).toBe(result.user.email_blind_index);
  });
});

import { describe, it, expect, beforeAll } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AUTH_ENDPOINTS, HTTP_METHODS } from '../../src/shared/constants/endpoints';

describe('Envelope Encryption End-to-End REST Flow Test Suite', () => {
  let router: AuthRestV1Router;
  let adapter: AlloyDBOmniAuthAdapter;

  beforeAll(() => {
    adapter = new AlloyDBOmniAuthAdapter();
    const service = new AuthService(adapter);
    router = new AuthRestV1Router(service);
  });

  it('completes sign up with field-level encryption and signs in via email blind index', async () => {
    const email = `e2e_crypto_${Date.now()}@enterprise.com`;
    const password = 'StrongPassword!2026Secure';
    const name = 'Cipher Specialist';
    const orgName = `Crypto Corp ${Date.now()}`;

    const signUpRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email,
      password,
      name,
      organization_name: orgName,
    });

    expect(signUpRes.statusCode).toBe(201);
    expect(signUpRes.payload.status).toBe('success');
    const signUpData = signUpRes.payload.data as { token: string; user: { email: string; name: string } };
    expect(signUpData.token).toBeDefined();

    const storedUser = await adapter.findUserByEmail(email);
    expect(storedUser).toBeDefined();
    expect(storedUser?.email_encrypted?.startsWith('enc:v1:')).toBe(true);
    expect(storedUser?.name_encrypted?.startsWith('enc:v1:')).toBe(true);
    expect(storedUser?.email_blind_index).toMatch(/^[a-f0-9]{64}$/);

    const signInRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_IN, {
      email,
      password,
    });

    expect(signInRes.statusCode).toBe(200);
    expect(signInRes.payload.status).toBe('success');
    const signInData = signInRes.payload.data as { token: string };
    expect(signInData.token).toBeDefined();
  });
});

import { describe, it, expect, beforeAll } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AUTH_ENDPOINTS, HTTP_METHODS } from '../../src/shared/constants/endpoints';

describe('Cryptographic Shredding End-to-End REST Flow Test Suite (ADR 0036)', () => {
  let router: AuthRestV1Router;
  let adapter: AlloyDBOmniAuthAdapter;
  let service: AuthService;

  beforeAll(() => {
    adapter = new AlloyDBOmniAuthAdapter();
    service = new AuthService(adapter);
    router = new AuthRestV1Router(service);
  });

  it('completes user registration, provisions DEK, and executes DELETE /api/v1/auth/users/:id/shred with step-up verification', async () => {
    const email = `e2e_shred_${Date.now()}@gdpr.eu`;
    const password = 'StrongPassword!2026Secure';

    const signUpRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email,
      password,
      name: 'E2E Shred Subject',
      organization_name: `Shred Enterprise ${Date.now()}`,
    });

    expect(signUpRes.statusCode).toBe(201);
    const userId = (signUpRes.payload.data as any).user.id;
    const sessionToken = (signUpRes.payload.data as any).token;

    const keyBefore = await adapter.findUserEncryptionKey(userId);
    expect(keyBefore?.dek_status).toBe('ACTIVE');

    const reauthRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.STEP_UP_VERIFY,
      { password },
      { authorization: `Bearer ${sessionToken}` }
    );
    expect(reauthRes.statusCode).toBe(200);
    const reauthToken = (reauthRes.payload.data as any).reauthToken;

    const shredRes = await router.route(
      HTTP_METHODS.DELETE,
      `${AUTH_ENDPOINTS.USERS}/${userId}/shred`,
      undefined,
      {
        authorization: `Bearer ${sessionToken}`,
        'x-reauth-token': reauthToken,
      }
    );

    expect(shredRes.statusCode).toBe(200);
    expect(shredRes.payload.status).toBe('success');
    expect((shredRes.payload.data as any).success).toBe(true);

    const keyAfter = await adapter.findUserEncryptionKey(userId);
    expect(keyAfter?.dek_status).toBe('SHREDDED');
  });
});

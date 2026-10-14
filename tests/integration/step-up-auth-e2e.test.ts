import { describe, it, expect } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { TotpMfaAdapter } from '../../src/infra/adapters/mfa/totp-mfa.adapter';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { generateReauthToken } from '../../src/shared/utils/jwt.util';

describe('RFC 9470 Step-Up Authentication Integration Tests', () => {
  const repo = new AlloyDBOmniAuthAdapter();
  const mfaAdapter = new TotpMfaAdapter();
  const authService = new AuthService(repo, undefined, undefined, undefined, undefined, undefined, undefined, mfaAdapter);
  const router = new AuthRestV1Router(authService);

  it('blocks high-value action (org delete) without reauth token with HTTP 403 and WWW-Authenticate header', async () => {
    const email = 'stepup.owner@company.io';
    const password = 'Password@123';

    const signUpRes = await router.route('POST', '/api/v1/auth/sign-up', {
      email,
      password,
      name: 'StepUp Owner',
      organization_name: 'Critical Infrastructure Ltd',
    });
    const sessionToken = (signUpRes.payload.data as any).token;
    const orgId = (signUpRes.payload.data as any).user.organization_id;

    const unauthenticatedDelete = await router.route(
      'DELETE',
      `/api/v1/auth/organizations/${orgId}`,
      {},
      { authorization: `Bearer ${sessionToken}` }
    );

    expect(unauthenticatedDelete.statusCode).toBe(403);
    expect(unauthenticatedDelete.headers?.['WWW-Authenticate']).toContain('StepUp max_age=300');
    expect(unauthenticatedDelete.payload.error?.code).toBe('STEP_UP_REQUIRED');

    const wrongCredsStepUp = await router.route(
      'POST',
      '/api/v1/auth/step-up/verify',
      { password: 'WrongPassword@999' },
      { authorization: `Bearer ${sessionToken}` }
    );
    expect(wrongCredsStepUp.statusCode).toBe(401);

    const validStepUp = await router.route(
      'POST',
      '/api/v1/auth/step-up/verify',
      { password },
      { authorization: `Bearer ${sessionToken}` }
    );
    expect(validStepUp.statusCode).toBe(200);
    const { reauthToken, expiresInSeconds } = validStepUp.payload.data as any;
    expect(reauthToken).toBeDefined();
    expect(expiresInSeconds).toBe(300);

    const authorizedDelete = await router.route(
      'DELETE',
      `/api/v1/auth/organizations/${orgId}`,
      {},
      {
        authorization: `Bearer ${sessionToken}`,
        'x-reauth-token': reauthToken,
      }
    );
    expect(authorizedDelete.statusCode).toBe(200);
  });

  it('protects super_secret API key creation requiring step-up reauthentication', async () => {
    const email = 'apikey.creator@company.io';
    const password = 'Password@123';

    const signUpRes = await router.route('POST', '/api/v1/auth/sign-up', {
      email,
      password,
      name: 'Key Creator',
      organization_name: 'Key Vaults Corp',
    });
    const sessionToken = (signUpRes.payload.data as any).token;
    const orgId = (signUpRes.payload.data as any).user.org_id;

    const rejectedSecretKey = await router.route(
      'POST',
      '/api/v1/auth/api-keys',
      {
        name: 'Root Secrets Key',
        org_id: orgId,
        key_type: 'super_secret',
        permissions: ['*'],
        expires_at_ms: Date.now() + 86400000,
      },
      { authorization: `Bearer ${sessionToken}` }
    );
    expect(rejectedSecretKey.statusCode).toBe(403);
    expect(rejectedSecretKey.headers?.['WWW-Authenticate']).toContain('StepUp max_age=300');

    const generalKeyNoStepUp = await router.route(
      'POST',
      '/api/v1/auth/api-keys',
      {
        name: 'General Ingestion Key',
        org_id: orgId,
        key_type: 'general',
        permissions: ['metrics:write'],
      },
      { authorization: `Bearer ${sessionToken}` }
    );
    expect(generalKeyNoStepUp.statusCode).toBe(201);

    const reauth = await router.route(
      'POST',
      '/api/v1/auth/step-up/verify',
      { password },
      { authorization: `Bearer ${sessionToken}` }
    );
    const reauthToken = (reauth.payload.data as any).reauthToken;

    const acceptedSecretKey = await router.route(
      'POST',
      '/api/v1/auth/api-keys',
      {
        name: 'Root Secrets Key',
        org_id: orgId,
        key_type: 'super_secret',
        permissions: ['*'],
        expires_at_ms: Date.now() + 86400000,
      },
      {
        authorization: `Bearer ${sessionToken}`,
        'x-reauth-token': reauthToken,
      }
    );
    expect(acceptedSecretKey.statusCode).toBe(201);
  });

  it('anti-tamper: rejects expired reauth tokens and tokens belonging to another user', async () => {
    const emailA = 'user.alpha@company.io';
    const emailB = 'user.beta@company.io';
    const password = 'Password@123';

    const resA = await router.route('POST', '/api/v1/auth/sign-up', {
      email: emailA, password, name: 'Alpha', organization_name: 'Alpha Org',
    });
    const tokenA = (resA.payload.data as any).token;
    const userAId = (resA.payload.data as any).user.id;
    const orgAId = (resA.payload.data as any).user.organization_id;

    const resB = await router.route('POST', '/api/v1/auth/sign-up', {
      email: emailB, password, name: 'Beta', organization_name: 'Beta Org',
    });
    const tokenB = (resB.payload.data as any).token;

    const reauthB = await router.route('POST', '/api/v1/auth/step-up/verify', { password }, {
      authorization: `Bearer ${tokenB}`,
    });
    const reauthTokenB = (reauthB.payload.data as any).reauthToken;

    const crossUserAttack = await router.route(
      'DELETE',
      `/api/v1/auth/organizations/${orgAId}`,
      {},
      {
        authorization: `Bearer ${tokenA}`,
        'x-reauth-token': reauthTokenB,
      }
    );
    expect(crossUserAttack.statusCode).toBe(403);

    const expiredToken = generateReauthToken(userAId, emailA, -60);
    const expiredAttack = await router.route(
      'DELETE',
      `/api/v1/auth/organizations/${orgAId}`,
      {},
      {
        authorization: `Bearer ${tokenA}`,
        'x-reauth-token': expiredToken,
      }
    );
    expect(expiredAttack.statusCode).toBe(403);
  });
});

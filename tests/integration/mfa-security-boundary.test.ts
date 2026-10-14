import { describe, it, expect } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { TotpMfaAdapter } from '../../src/infra/adapters/mfa/totp-mfa.adapter';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { generateMfaChallengeToken } from '../../src/shared/utils/jwt.util';

describe('Deep Critical Security & Boundary Tests for MFA', () => {
  const repo = new AlloyDBOmniAuthAdapter();
  const mfaAdapter = new TotpMfaAdapter();
  const authService = new AuthService(repo, undefined, undefined, undefined, undefined, undefined, undefined, mfaAdapter);
  const router = new AuthRestV1Router(authService);

  it('boundary & tamper tests: rejects malformed, expired, forged, and cross-user MFA tokens', async () => {
    const email = 'tamper.target@test.org';
    const password = 'Password@123';

    const signUpRes = await router.route('POST', '/api/v1/auth/sign-up', {
      email,
      password,
      name: 'Tamper Target',
      organization_name: 'Defense Org',
    });
    const sessionToken = (signUpRes.payload.data as any).token;

    const setupRes = await router.route('POST', '/api/v1/auth/mfa/setup', {}, {
      authorization: `Bearer ${sessionToken}`,
    });
    const { secret } = setupRes.payload.data as any;

    const counter = Math.floor(Date.now() / 1000 / 30);
    const validOtp = mfaAdapter.generateCodeForCounter(secret, counter);

    await router.route('POST', '/api/v1/auth/mfa/verify', { code: validOtp }, {
      authorization: `Bearer ${sessionToken}`,
    });

    const secondSetup = await router.route('POST', '/api/v1/auth/mfa/setup', {}, {
      authorization: `Bearer ${sessionToken}`,
    });
    expect(secondSetup.statusCode).toBe(409);

    const expiredToken = generateMfaChallengeToken('fake_user', 'fake@test.org', 'fake_org', 'member', -100);
    const expiredRes = await router.route('POST', '/api/v1/auth/mfa/challenge', {
      mfa_token: expiredToken,
      code: '123456',
    });
    expect(expiredRes.statusCode).toBe(401);

    const forgedToken = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.invalidsig';
    const forgedRes = await router.route('POST', '/api/v1/auth/mfa/challenge', {
      mfa_token: forgedToken,
      code: '123456',
    });
    expect(forgedRes.statusCode).toBe(401);

    const loginRes = await router.route('POST', '/api/v1/auth/sign-in', {
      email,
      password,
    });
    const validMfaToken = (loginRes.payload.data as any).mfa_token;

    const wrongOtpRes = await router.route('POST', '/api/v1/auth/mfa/challenge', {
      mfa_token: validMfaToken,
      code: '999999',
    });
    expect(wrongOtpRes.statusCode).toBe(400);

    const wrongFormatRes = await router.route('POST', '/api/v1/auth/mfa/challenge', {
      mfa_token: validMfaToken,
      code: '123',
    });
    expect(wrongFormatRes.statusCode).toBe(400);

    const sqlInjRes = await router.route('POST', '/api/v1/auth/mfa/challenge', {
      mfa_token: validMfaToken,
      code: "' OR '1'='1",
    });
    expect(sqlInjRes.statusCode).toBe(400);
  });

  it('anti-tamper: ensures recovery codes cannot be used by a different user', async () => {
    const userAEmail = 'user.a@test.org';
    const userBEmail = 'user.b@test.org';
    const password = 'Password@123';

    const resA = await router.route('POST', '/api/v1/auth/sign-up', {
      email: userAEmail,
      password,
      name: 'User A',
      organization_name: 'Org A',
    });
    const tokenA = (resA.payload.data as any).token;

    const resB = await router.route('POST', '/api/v1/auth/sign-up', {
      email: userBEmail,
      password,
      name: 'User B',
      organization_name: 'Org B',
    });
    const tokenB = (resB.payload.data as any).token;

    const setupA = await router.route('POST', '/api/v1/auth/mfa/setup', {}, { authorization: `Bearer ${tokenA}` });
    const secretA = (setupA.payload.data as any).secret;
    const otpA = mfaAdapter.generateCodeForCounter(secretA, Math.floor(Date.now() / 1000 / 30));
    const verifyA = await router.route('POST', '/api/v1/auth/mfa/verify', { code: otpA }, { authorization: `Bearer ${tokenA}` });
    const recoveryCodesA = (verifyA.payload.data as any).recoveryCodes as string[];

    const setupB = await router.route('POST', '/api/v1/auth/mfa/setup', {}, { authorization: `Bearer ${tokenB}` });
    const secretB = (setupB.payload.data as any).secret;
    const otpB = mfaAdapter.generateCodeForCounter(secretB, Math.floor(Date.now() / 1000 / 30));
    await router.route('POST', '/api/v1/auth/mfa/verify', { code: otpB }, { authorization: `Bearer ${tokenB}` });

    const loginB = await router.route('POST', '/api/v1/auth/sign-in', { email: userBEmail, password });
    const mfaTokenB = (loginB.payload.data as any).mfa_token;

    const attackRes = await router.route('POST', '/api/v1/auth/mfa/challenge', {
      mfa_token: mfaTokenB,
      code: recoveryCodesA[0]!,
    });
    expect(attackRes.statusCode).toBe(400);
  });
});

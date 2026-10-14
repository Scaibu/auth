import { describe, it, expect } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { TotpMfaAdapter } from '../../src/infra/adapters/mfa/totp-mfa.adapter';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('MFA End-to-End Integration Tests', () => {
  const repo = new AlloyDBOmniAuthAdapter();
  const mfaAdapter = new TotpMfaAdapter();
  const authService = new AuthService(repo, undefined, undefined, undefined, undefined, undefined, undefined, mfaAdapter);
  const router = new AuthRestV1Router(authService);

  it('completes entire MFA lifecycle: setup -> verify -> login challenge with TOTP and recovery code', async () => {
    const email = 'mfa.user@test.org';
    const password = 'Password@123';

    const signUpRes = await router.route('POST', '/api/v1/auth/sign-up', {
      email,
      password,
      name: 'MFA Tester',
      organization_name: 'MFA Corp',
    });
    expect(signUpRes.statusCode).toBe(201);
    const sessionToken = (signUpRes.payload.data as any).token;

    const setupRes = await router.route('POST', '/api/v1/auth/mfa/setup', {}, {
      authorization: `Bearer ${sessionToken}`,
    });
    expect(setupRes.statusCode).toBe(200);
    const { secret, otpauthUrl } = setupRes.payload.data as any;
    expect(secret).toBeDefined();
    expect(otpauthUrl).toContain('otpauth://totp/');

    const counter = Math.floor(Date.now() / 1000 / 30);
    const currentOtp = mfaAdapter.generateCodeForCounter(secret, counter);

    const verifyRes = await router.route('POST', '/api/v1/auth/mfa/verify', { code: currentOtp }, {
      authorization: `Bearer ${sessionToken}`,
    });
    expect(verifyRes.statusCode).toBe(200);
    const { mfaEnabled, recoveryCodes } = verifyRes.payload.data as any;
    expect(mfaEnabled).toBe(true);
    expect(recoveryCodes).toHaveLength(10);

    const loginRes = await router.route('POST', '/api/v1/auth/sign-in', {
      email,
      password,
    });
    expect(loginRes.statusCode).toBe(200);
    const loginData = loginRes.payload.data as any;
    expect(loginData.mfa_required).toBe(true);
    expect(loginData.mfa_token).toBeDefined();

    const freshCounter = Math.floor(Date.now() / 1000 / 30);
    const freshOtp = mfaAdapter.generateCodeForCounter(secret, freshCounter);
    const challengeRes = await router.route('POST', '/api/v1/auth/mfa/challenge', {
      mfa_token: loginData.mfa_token,
      code: freshOtp,
    });
    expect(challengeRes.statusCode).toBe(200);
    const finalSession = challengeRes.payload.data as any;
    expect(finalSession.token).toBeDefined();
    expect(finalSession.user.email).toBe(email);
    expect(finalSession.usedRecoveryCode).toBe(false);

    const loginRes2 = await router.route('POST', '/api/v1/auth/sign-in', {
      email,
      password,
    });
    const mfaToken2 = (loginRes2.payload.data as any).mfa_token;
    const singleUseCode = recoveryCodes[0]!;

    const recoveryChallengeRes = await router.route('POST', '/api/v1/auth/mfa/challenge', {
      mfa_token: mfaToken2,
      code: singleUseCode,
    });
    expect(recoveryChallengeRes.statusCode).toBe(200);
    expect((recoveryChallengeRes.payload.data as any).usedRecoveryCode).toBe(true);

    const loginRes3 = await router.route('POST', '/api/v1/auth/sign-in', {
      email,
      password,
    });
    const mfaToken3 = (loginRes3.payload.data as any).mfa_token;
    const replayedRecoveryRes = await router.route('POST', '/api/v1/auth/mfa/challenge', {
      mfa_token: mfaToken3,
      code: singleUseCode,
    });
    expect(replayedRecoveryRes.statusCode).toBe(400);
  });
});

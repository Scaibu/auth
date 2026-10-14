import { describe, it, expect, beforeEach } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { MockBreachedPasswordAdapter } from '../../src/infra/adapters/security/mock-pwned-passwords.adapter';
import { HTTP_METHODS, AUTH_ENDPOINTS } from '../../src/shared/constants/endpoints';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('Breached Password Screening Scenarios & Attack Vectors', () => {
  let router: AuthRestV1Router;
  let service: AuthService;
  let mockBreachDetector: MockBreachedPasswordAdapter;

  beforeEach(() => {
    const repo = new AlloyDBOmniAuthAdapter();
    mockBreachDetector = new MockBreachedPasswordAdapter([
      'Password123!',
      'PwnedPass123!@#',
      'Admin123456!',
      'LeakedCredentials2024!',
    ]);

    service = new AuthService(
      repo,
      undefined,
      undefined,
      {
        rateLimit: { maxAttemptsPerIp: 10, ipWindowMs: 60000, maxFailedPerEmail: 5, emailLockoutMs: 60000, emailCaptchaThreshold: 3 },
        sessionDenylist: { keyPrefix: 'auth:denylist:', defaultTtlSeconds: 3600 },
        breachedPassword: {
          enabled: true,
          baseUrl: 'https://api.pwnedpasswords.com/range',
          timeoutMs: 1000,
          userAgent: 'llm-observability-auth/1.0.0',
        },
      },
      undefined,
      undefined,
      undefined,
      undefined,
      mockBreachDetector,
    );

    router = new AuthRestV1Router(service);
  });

  it('Scenario 1: Credential Stuffing Vector — blocks sign-up with public dictionary password', async () => {
    const res = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: 'victim@enterprise.com',
      password: 'Password123!',
      name: 'Victim User',
      organization_name: 'Enterprise Inc',
    });

    expect(res.statusCode).toBe(400);
    expect(res.payload.success).toBe(false);
    expect(res.payload.error?.code).toBe('PASSWORD_BREACHED');
    expect(res.payload.message).toContain('found in known public data breaches');
  });

  it('Scenario 2: Account Takeover via Forgot-Password Reset — blocks resetting to breached credential', async () => {
    // 1. Legitimate user registration with strong unbreached password
    const signUpRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: 'target_employee@enterprise.com',
      password: 'SuperSecureUnbreachedPassword2026!#',
      name: 'Employee Target',
      organization_name: 'Corp Secure',
    });
    expect(signUpRes.statusCode).toBe(201);

    // 2. Request reset token
    const forgotRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.FORGOT_PASSWORD, {
      email: 'target_employee@enterprise.com',
    });
    expect(forgotRes.statusCode).toBe(200);
    const resetToken = (forgotRes.payload.data as any).resetToken;
    expect(resetToken).toBeDefined();

    // 3. Attempt reset using breached password
    const resetRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.RESET_PASSWORD, {
      token: resetToken,
      new_password: 'LeakedCredentials2024!',
    });

    expect(resetRes.statusCode).toBe(400);
    expect(resetRes.payload.error?.code).toBe('PASSWORD_BREACHED');
  });

  it('Scenario 3: In-Session Password Downgrade — blocks authenticated user changing to breached password', async () => {
    // 1. Sign up user
    const signUpRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: 'admin_security@enterprise.com',
      password: 'SuperSecureUnbreachedPassword2026!#',
      name: 'Sec Admin',
      organization_name: 'Security Ops',
    });
    expect(signUpRes.statusCode).toBe(201);
    const token = (signUpRes.payload.data as any).token;

    // 2. Attempt change password to known breached password
    const changeRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.CHANGE_PASSWORD,
      {
        current_password: 'SuperSecureUnbreachedPassword2026!#',
        new_password: 'Admin123456!',
      },
      {
        [AUTH_CONSTANTS.HEADERS.AUTHORIZATION]: `${AUTH_CONSTANTS.HEADERS.BEARER_PREFIX}${token}`,
      },
    );

    expect(changeRes.statusCode).toBe(400);
    expect(changeRes.payload.error?.code).toBe('PASSWORD_BREACHED');
  });

  it('Scenario 4: Valid Clean Password Cycle — allows registration, rotation, and subsequent sign-in', async () => {
    const email = 'clean_user@enterprise.com';
    const pwd1 = 'CleanInitialPassword2026!#';
    const pwd2 = 'RotatedCleanPassword2026!@$';

    // 1. Sign up
    const signUpRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email,
      password: pwd1,
      name: 'Clean User',
      organization_name: 'Clean Enterprises',
    });
    expect(signUpRes.statusCode).toBe(201);
    const token = (signUpRes.payload.data as any).token;

    // 2. Change password
    const changeRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.CHANGE_PASSWORD,
      {
        current_password: pwd1,
        new_password: pwd2,
      },
      {
        [AUTH_CONSTANTS.HEADERS.AUTHORIZATION]: `${AUTH_CONSTANTS.HEADERS.BEARER_PREFIX}${token}`,
      },
    );
    expect(changeRes.statusCode).toBe(200);

    // 3. Sign in with updated password
    const signInRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_IN, {
      email,
      password: pwd2,
    });
    expect(signInRes.statusCode).toBe(200);
    expect((signInRes.payload.data as any).token).toBeDefined();
  });
});

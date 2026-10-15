import { describe, it, expect, beforeEach } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { HTTP_METHODS, AUTH_ENDPOINTS } from '../../src/shared/constants/endpoints';

describe('NIST SP 800-63B Password History Enforcement & Cyclic Reuse Prevention', () => {
  let router: AuthRestV1Router;
  let service: AuthService;
  let repo: AlloyDBOmniAuthAdapter;

  beforeEach(() => {
    repo = new AlloyDBOmniAuthAdapter();
    service = new AuthService(
      repo,
      undefined,
      undefined,
      {
        rateLimit: { maxAttemptsPerIp: 100, ipWindowMs: 60000, maxFailedPerEmail: 50, emailLockoutMs: 60000, emailCaptchaThreshold: 30 },
        sessionDenylist: { keyPrefix: 'auth:denylist:', defaultTtlSeconds: 3600 },
        breachedPassword: { enabled: false },
      },
    );
    router = new AuthRestV1Router(service);
  });

  it('rejects changing password to the current password with PASSWORD_RECENTLY_USED', async () => {
    const signUpRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: 'history_test_1@example.com',
      password: 'InitialPassword123!',
      name: 'History User 1',
      organization_name: 'History Org 1',
    });
    expect(signUpRes.statusCode).toBe(201);
    const token = signUpRes.payload.data.token;

    const changeRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.CHANGE_PASSWORD,
      {
        current_password: 'InitialPassword123!',
        new_password: 'InitialPassword123!',
      },
      { authorization: `Bearer ${token}` },
    );

    expect(changeRes.statusCode).toBe(400);
    expect(changeRes.payload.success).toBe(false);
    expect(changeRes.payload.error?.code).toBe('PASSWORD_RECENTLY_USED');
    expect(changeRes.payload.message).toContain('You cannot reuse any of your last 10 passwords');
  });

  it('enforces retention history window: rejects reuse of any of the last 10 passwords and permits reuse after FIFO eviction', async () => {
    const signUpRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: 'history_fifo_test@example.com',
      password: 'PassGeneration_00!',
      name: 'FIFO User',
      organization_name: 'FIFO Org',
    });
    expect(signUpRes.statusCode).toBe(201);
    const token = signUpRes.payload.data.token;

    let currentPass = 'PassGeneration_00!';
    for (let i = 1; i <= 10; i++) {
      const nextPass = `PassGeneration_${i.toString().padStart(2, '0')}!`;
      const changeRes = await router.route(
        HTTP_METHODS.POST,
        AUTH_ENDPOINTS.CHANGE_PASSWORD,
        {
          current_password: currentPass,
          new_password: nextPass,
        },
        { authorization: `Bearer ${token}` },
      );
      expect(changeRes.statusCode).toBe(200);
      expect(changeRes.payload.success).toBe(true);
      currentPass = nextPass;
    }

    const rejectOldRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.CHANGE_PASSWORD,
      {
        current_password: currentPass,
        new_password: 'PassGeneration_05!',
      },
      { authorization: `Bearer ${token}` },
    );
    expect(rejectOldRes.statusCode).toBe(400);
    expect(rejectOldRes.payload.error?.code).toBe('PASSWORD_RECENTLY_USED');

    const evictOldestChange = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.CHANGE_PASSWORD,
      {
        current_password: currentPass,
        new_password: 'PassGeneration_11!',
      },
      { authorization: `Bearer ${token}` },
    );
    expect(evictOldestChange.statusCode).toBe(200);
    currentPass = 'PassGeneration_11!';

    const reuseEvictedRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.CHANGE_PASSWORD,
      {
        current_password: currentPass,
        new_password: 'PassGeneration_00!',
      },
      { authorization: `Bearer ${token}` },
    );
    expect(reuseEvictedRes.statusCode).toBe(200);
    expect(reuseEvictedRes.payload.success).toBe(true);
  });

  it('rejects password reset if presented token sets a recently used password', async () => {
    const signUpRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: 'reset_history_test@example.com',
      password: 'ResetInitialPass123!',
      name: 'Reset History User',
      organization_name: 'Reset History Org',
    });
    expect(signUpRes.statusCode).toBe(201);
    const token = signUpRes.payload.data.token;

    const changeRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.CHANGE_PASSWORD,
      {
        current_password: 'ResetInitialPass123!',
        new_password: 'ResetRotatedPass456!',
      },
      { authorization: `Bearer ${token}` },
    );
    expect(changeRes.statusCode).toBe(200);

    const forgotRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.FORGOT_PASSWORD, {
      email: 'reset_history_test@example.com',
    });
    expect(forgotRes.statusCode).toBe(200);
    const resetToken = forgotRes.payload.data.resetToken;
    expect(resetToken).toBeDefined();

    const resetCurrentReject = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.RESET_PASSWORD, {
      token: resetToken,
      new_password: 'ResetRotatedPass456!',
    });
    expect(resetCurrentReject.statusCode).toBe(400);
    expect(resetCurrentReject.payload.error?.code).toBe('PASSWORD_RECENTLY_USED');

    const resetHistoryReject = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.RESET_PASSWORD, {
      token: resetToken,
      new_password: 'ResetInitialPass123!',
    });
    expect(resetHistoryReject.statusCode).toBe(400);
    expect(resetHistoryReject.payload.error?.code).toBe('PASSWORD_RECENTLY_USED');

    const resetSuccess = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.RESET_PASSWORD, {
      token: resetToken,
      new_password: 'BrandNewUnusedPassword789!',
    });
    expect(resetSuccess.statusCode).toBe(200);
    expect(resetSuccess.payload.success).toBe(true);
  });
});

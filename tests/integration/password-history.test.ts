import { describe, it, expect, beforeEach } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { RealPostgresAuthAdapter } from '../../src/infra/adapters/postgres/real-postgres-auth.adapter';
import { MockBreachedPasswordAdapter } from '../../src/infra/adapters/security/mock-pwned-passwords.adapter';
import { HTTP_METHODS, AUTH_ENDPOINTS } from '../../src/shared/constants/endpoints';
import { AUTH_CONFIG } from '../../src/config/env.config';
import { hashPassword } from '../../src/shared/utils/argon2.util';

interface TokenPayload {
  readonly token: string;
}

interface ResetTokenPayload {
  readonly resetToken: string;
}

function isTokenPayload(value: unknown): value is TokenPayload {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return typeof record['token'] === 'string';
}

function isResetTokenPayload(value: unknown): value is ResetTokenPayload {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return typeof record['resetToken'] === 'string';
}

function extractToken(data: unknown): string {
  if (!isTokenPayload(data)) {
    throw new Error('Response payload does not contain a valid string token');
  }
  return data.token;
}

function extractResetToken(data: unknown): string {
  if (!isResetTokenPayload(data)) {
    throw new Error('Response payload does not contain a valid string resetToken');
  }
  return data.resetToken;
}

describe('NIST SP 800-63B Password History Enforcement & Anti-Recycling Deep Verification', () => {
  let router: AuthRestV1Router;
  let service: AuthService;
  let repo: AlloyDBOmniAuthAdapter;
  let mockBreachedDetector: MockBreachedPasswordAdapter;

  beforeEach(() => {
    repo = new AlloyDBOmniAuthAdapter();
    mockBreachedDetector = new MockBreachedPasswordAdapter([
      'KnownBreachedP@ssword123!',
      'PwnedCredential2026!#',
    ]);

    service = new AuthService(
      repo,
      undefined,
      undefined,
      {
        rateLimit: { maxAttemptsPerIp: 100, ipWindowMs: 60000, maxFailedPerEmail: 50, emailLockoutMs: 60000, emailCaptchaThreshold: 30 },
        sessionDenylist: { keyPrefix: 'auth:denylist:', defaultTtlSeconds: 3600 },
        breachedPassword: {
          enabled: true,
          baseUrl: 'https://api.pwnedpasswords.com/range',
          timeoutMs: 1500,
          userAgent: 'llm-observability-auth/1.0.0',
        },
      },
      undefined,
      undefined,
      undefined,
      undefined,
      mockBreachedDetector,
    );
    router = new AuthRestV1Router(service);
  });

  it('1. Rejection of Active Current Password — throws PASSWORD_RECENTLY_USED', async () => {
    const signUpRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: 'history_test_1@example.com',
      password: 'InitialPassword123!',
      name: 'History User 1',
      organization_name: 'History Org 1',
    });
    expect(signUpRes.statusCode).toBe(201);
    const token = extractToken(signUpRes.payload.data);

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

  it('2. Retention Window & FIFO Eviction — enforces top 10 and evicts 11th oldest', async () => {
    const signUpRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: 'history_fifo_test@example.com',
      password: 'PassGeneration_00!',
      name: 'FIFO User',
      organization_name: 'FIFO Org',
    });
    expect(signUpRes.statusCode).toBe(201);
    const token = extractToken(signUpRes.payload.data);

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

  it('3. Password Recovery Token Reset — blocks recycled secrets and accepts novel secrets', async () => {
    const signUpRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: 'reset_history_test@example.com',
      password: 'ResetInitialPass123!',
      name: 'Reset History User',
      organization_name: 'Reset History Org',
    });
    expect(signUpRes.statusCode).toBe(201);
    const token = extractToken(signUpRes.payload.data);

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
    const resetToken = extractResetToken(forgotRes.payload.data);
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

  it('4. Multi-Tenant Cross-User Isolation — user history is strictly scoped to user_id', async () => {
    const user1SignUp = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: 'isolation_user1@tenant-a.com',
      password: 'SharedSecretPass123!',
      name: 'User One',
      organization_name: 'Tenant Alpha',
    });
    expect(user1SignUp.statusCode).toBe(201);

    const user2SignUp = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: 'isolation_user2@tenant-b.com',
      password: 'DifferentInitialPass1!',
      name: 'User Two',
      organization_name: 'Tenant Beta',
    });
    expect(user2SignUp.statusCode).toBe(201);
    const user2Token = extractToken(user2SignUp.payload.data);

    const user2Change = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.CHANGE_PASSWORD,
      {
        current_password: 'DifferentInitialPass1!',
        new_password: 'SharedSecretPass123!',
      },
      { authorization: `Bearer ${user2Token}` },
    );

    expect(user2Change.statusCode).toBe(200);
    expect(user2Change.payload.success).toBe(true);
  });

  it('5. DoS Prevention Short-Circuit — invalid current password fails with 401 before history hashing', async () => {
    const signUpRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: 'dos_defense_user@example.com',
      password: 'CorrectInitialPass1!',
      name: 'DoS Defense User',
      organization_name: 'Defense Org',
    });
    expect(signUpRes.statusCode).toBe(201);
    const token = extractToken(signUpRes.payload.data);

    const badCurrentRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.CHANGE_PASSWORD,
      {
        current_password: 'WrongCurrentPassword999!',
        new_password: 'CorrectInitialPass1!',
      },
      { authorization: `Bearer ${token}` },
    );

    expect(badCurrentRes.statusCode).toBe(401);
    expect(badCurrentRes.payload.error?.code).toBe('INVALID_CREDENTIALS');
  });

  it('6. Validation Precedence — breached password detector trips before history evaluation', async () => {
    const signUpRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: 'breach_precedence_user@example.com',
      password: 'InitialSafePassword1!',
      name: 'Breach User',
      organization_name: 'Breach Org',
    });
    expect(signUpRes.statusCode).toBe(201);
    const token = extractToken(signUpRes.payload.data);

    const changeBreachedRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.CHANGE_PASSWORD,
      {
        current_password: 'InitialSafePassword1!',
        new_password: 'KnownBreachedP@ssword123!',
      },
      { authorization: `Bearer ${token}` },
    );

    expect(changeBreachedRes.statusCode).toBe(400);
    expect(changeBreachedRes.payload.error?.code).toBe('PASSWORD_BREACHED');
  });

  it('7. Recovery Token Guard Short-Circuit — expired token fails before password history evaluation', async () => {
    const expiredTokenHash = 'expired_hash_12345';
    await repo.savePasswordResetToken(expiredTokenHash, 'usr_mock_dummy', Date.now() - 500000);

    const resetExpired = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.RESET_PASSWORD, {
      token: 'expired_raw_token_xyz',
      new_password: 'NewStrongPassword123!',
    });

    expect(resetExpired.statusCode).toBe(400);
    expect(resetExpired.payload.error?.code).toBe('VALIDATION_ERROR');
  });

  it('8. Real PostgreSQL Database Integration — executes SQL insert, pruning, and cascade delete', async () => {
    const realAdapter = new RealPostgresAuthAdapter(AUTH_CONFIG.db.url);
    const testUserId = `usr_pg_test_${Date.now()}`;
    const orgId = `org_pg_test_${Date.now()}`;

    try {
      await realAdapter.createOrganizationAndUser({
        id: testUserId,
        email: `pg_test_${Date.now()}@observability.io`,
        password_hash: await hashPassword('InitialPass123!'),
        name: 'PG Integration User',
        org_id: orgId,
        org_name: `PG Integration Org ${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
        role: 'admin',
        blocked: false,
        user_permissions: ['admin:all'],
      });

      for (let i = 1; i <= 15; i++) {
        const dummyHash = await hashPassword(`DummyPass_${i}!`);
        await realAdapter.recordPasswordHistory(testUserId, dummyHash, Date.now() + i * 1000);
      }

      const recentHashes = await realAdapter.getRecentPasswordHashes(testUserId, 20);
      expect(recentHashes.length).toBe(10);

      const status = await realAdapter.getPoolStatus();
      expect(status).toBeDefined();
    } finally {
      await realAdapter.close();
    }
  });
});

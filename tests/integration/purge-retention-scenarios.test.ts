import { describe, it, expect, beforeEach } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { MockBreachedPasswordAdapter } from '../../src/infra/adapters/security/mock-pwned-passwords.adapter';

describe('Admin Retention Purge Scenarios (GDPR Article 17)', () => {
  let router: AuthRestV1Router;
  let service: AuthService;
  let repo: AlloyDBOmniAuthAdapter;
  let adminToken: string;
  let reauthToken: string;

  beforeEach(async () => {
    repo = new AlloyDBOmniAuthAdapter();
    const mockBreach = new MockBreachedPasswordAdapter([]);
    service = new AuthService(
      repo,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      mockBreach
    );
    router = new AuthRestV1Router(service);

    // Sign up admin
    const signUpRes = await router.route('POST', '/api/v1/auth/sign-up', {
      email: 'admin_purge@example.com',
      password: 'StrongAdminPass123!',
      name: 'Purge Admin',
      organization_name: 'Purge Corp',
    });
    adminToken = (signUpRes.payload.data as any).token;

    // Issue Step-Up reauth token for high-value action
    const stepUpRes = await router.route(
      'POST',
      '/api/v1/auth/step-up/verify',
      {
        password: 'StrongAdminPass123!',
      },
      {
        authorization: `Bearer ${adminToken}`,
      }
    );
    reauthToken = (stepUpRes.payload.data as any).reauthToken;
  });

  it('rejects purge execution without step-up authentication token (403 STEP_UP_REQUIRED)', async () => {
    const res = await router.route(
      'POST',
      '/api/v1/auth/admin/purge-expired',
      {},
      {
        authorization: `Bearer ${adminToken}`,
      }
    );

    expect(res.statusCode).toBe(403);
    expect(res.payload.status).toBe('error');
    expect(res.payload.error?.code).toBe('STEP_UP_REQUIRED');
  });

  it('successfully executes cascade purge when authorized with valid step-up token', async () => {
    const res = await router.route(
      'POST',
      '/api/v1/auth/admin/purge-expired',
      {},
      {
        authorization: `Bearer ${adminToken}`,
        'x-reauth-token': reauthToken,
      }
    );

    expect(res.statusCode).toBe(200);
    expect(res.payload.status).toBe('success');
    expect(res.payload.data).toHaveProperty('purged_records');
    expect(res.payload.data).toHaveProperty('cutoff_timestamp');
    expect(res.payload.data).toHaveProperty('duration_ms');
  });
});

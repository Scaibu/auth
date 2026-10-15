import { describe, it, expect, beforeAll } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { MockGeoIpAdapter } from '../../src/infra/adapters/geo/mock-geo-ip.adapter';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AUTH_ENDPOINTS, HTTP_METHODS } from '../../src/shared/constants/endpoints';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('Adaptive Risk-Based Authentication End-to-End API Tests', () => {
  let router: AuthRestV1Router;
  let service: AuthService;
  let geoIp: MockGeoIpAdapter;

  const testEmail = 'e2e.risk.user@example.com';
  const testPassword = 'StrongPassword999!';

  beforeAll(async () => {
    const repo = new AlloyDBOmniAuthAdapter();
    geoIp = new MockGeoIpAdapter();
    service = new AuthService(
      repo,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      geoIp,
    );
    router = new AuthRestV1Router(service);

    await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: testEmail,
      password: testPassword,
      name: 'E2E Risk User',
      organization_name: 'Risk Corp',
    });
  });

  it('performs low-risk login and receives session JWT directly', async () => {
    const response = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.SIGN_IN,
      {
        email: testEmail,
        password: testPassword,
      },
      {
        'x-forwarded-for': '10.0.0.1',
        'user-agent': 'Chrome/118.0.0.0',
      },
    );

    expect(response.statusCode).toBe(200);
    const data = response.payload.data as any;
    expect(data.status).toBe(AUTH_CONSTANTS.RISK.STATUS_AUTHENTICATED);
    expect(data.token).toBeDefined();
    expect(data.refreshToken).toBeDefined();
  });

  it('triggers soft step-up challenge and successfully resolves via POST /challenge/resolve', async () => {
    // Datacenter IP triggers soft step-up challenge
    const challengeRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.SIGN_IN,
      {
        email: testEmail,
        password: testPassword,
      },
      {
        'x-forwarded-for': '198.51.100.5',
        'user-agent': 'Chrome/118.0.0.0',
      },
    );

    expect(challengeRes.statusCode).toBe(200);
    const challengeData = challengeRes.payload.data as any;
    expect(challengeData.status).toBe(AUTH_CONSTANTS.RISK.STATUS_STEP_UP_REQUIRED);
    expect(challengeData.step_up_required).toBe(true);
    expect(challengeData.challenge_token).toBeDefined();
    expect(challengeData.risk_score).toBe(40);

    // Resolve via API
    const resolveRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.CHALLENGE_RESOLVE,
      {
        challenge_token: challengeData.challenge_token,
        verification_code: AUTH_CONSTANTS.RISK.DEFAULT_VERIFICATION_CODE,
      },
      {
        'x-forwarded-for': '198.51.100.5',
        'user-agent': 'Chrome/118.0.0.0',
      },
    );

    expect(resolveRes.statusCode).toBe(200);
    const resolveData = resolveRes.payload.data as any;
    expect(resolveData.token).toBeDefined();
    expect(resolveData.refreshToken).toBeDefined();
    expect(resolveData.user.email).toBe(testEmail);
  });

  it('rejects high-risk sign-in attempt with HTTP 403 Forbidden', async () => {
    // Seed previous login from San Francisco 5 minutes ago
    const user = await (service as any).repo.findUserByEmail(testEmail);
    await (service as any).repo.recordLoginHistory({
      id: 'lh_e2e_prev',
      userId: user.id,
      ipAddress: '10.0.0.1',
      latitude: 37.7749,
      longitude: -122.4194,
      isDatacenter: false,
      deviceFingerprint: 'seed_prev_fp',
      riskScore: 0,
      createdAtMs: Date.now() - 5 * 60 * 1000,
    });

    // Tokyo proxy 5 minutes after SF login: 40 (datacenter) + 35 (velocity) = 75 risk
    geoIp.setOverride('198.51.100.88', {
      ip: '198.51.100.88',
      latitude: 35.6762,
      longitude: 139.6503,
      asn: 'AS16509',
      isDatacenter: true,
    });

    const response = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.SIGN_IN,
      {
        email: testEmail,
        password: testPassword,
      },
      {
        'x-forwarded-for': '198.51.100.88',
        'user-agent': 'UnknownBot/1.0',
      },
    );

    expect(response.statusCode).toBe(403);
    expect(response.payload.error?.code).toBe('HIGH_RISK_SIGNIN_BLOCKED');
  });
});

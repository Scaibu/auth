import { describe, it, expect, beforeAll } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { MockGeoIpAdapter } from '../../src/infra/adapters/geo/mock-geo-ip.adapter';
import { HighRiskSignInBlockedError } from '../../src/shared/errors/auth.errors';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('Adaptive Risk-Based Authentication Integration Tests', () => {
  let repo: AlloyDBOmniAuthAdapter;
  let geoIp: MockGeoIpAdapter;
  let service: AuthService;

  const testEmail = 'adaptive.user@example.com';
  const testPassword = 'SecurePassword123!';

  beforeAll(async () => {
    repo = new AlloyDBOmniAuthAdapter();
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

    await service.signUp({
      email: testEmail,
      password: testPassword,
      name: 'Adaptive Tester',
      organization_name: 'Adaptive Defense Corp',
    });
  });

  it('allows seamless login from trusted IP with low risk (< 30)', async () => {
    const res: any = await service.signIn({
      email: testEmail,
      password: testPassword,
      ip_address: '10.0.0.1',
      user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    });

    expect(res.token).toBeDefined();
    expect(res.status).toBe(AUTH_CONSTANTS.RISK.STATUS_AUTHENTICATED);

    const latest = await repo.getLatestLoginLocation(res.user.id);
    expect(latest).not.toBeNull();
    expect(latest?.ipAddress).toBe('10.0.0.1');
    expect(latest?.riskScore).toBe(0);
  });

  it('triggers soft step-up challenge when datacenter proxy IP connects (30 <= risk < 75)', async () => {
    // 198.51.100.1 is configured as Datacenter in MockGeoIpAdapter
    const res: any = await service.signIn({
      email: testEmail,
      password: testPassword,
      ip_address: '198.51.100.1',
      user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    });

    expect(res.token).toBeUndefined();
    expect(res.step_up_required).toBe(true);
    expect(res.status).toBe(AUTH_CONSTANTS.RISK.STATUS_STEP_UP_REQUIRED);
    expect(res.challenge_token).toBeDefined();
    expect(res.risk_score).toBe(AUTH_CONSTANTS.RISK.FACTORS.DATACENTER_ASN);

    // Resolve challenge with verification code
    const resolved: any = await service.resolveRiskChallenge(
      res.challenge_token,
      AUTH_CONSTANTS.RISK.DEFAULT_VERIFICATION_CODE,
      '198.51.100.1',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    );

    expect(resolved.token).toBeDefined();
    expect(resolved.user.email).toBe(testEmail);
  });

  it('blocks authentication outright when extreme impossible travel and proxy combine (risk >= 75)', async () => {
    // Seed previous location: San Francisco, 5 minutes ago
    const user = await repo.findUserByEmail(testEmail);
    expect(user).not.toBeNull();

    await repo.recordLoginHistory({
      id: 'lh_seed',
      userId: user!.id,
      ipAddress: '10.0.0.5',
      latitude: 37.7749,
      longitude: -122.4194,
      isDatacenter: false,
      deviceFingerprint: 'seed_fingerprint',
      riskScore: 0,
      createdAtMs: Date.now() - 5 * 60 * 1000,
    });

    // Attempt signin from Tokyo via Datacenter IP 5 minutes later
    geoIp.setOverride('198.51.100.99', {
      ip: '198.51.100.99',
      latitude: 35.6762,
      longitude: 139.6503,
      asn: 'AS16509',
      isDatacenter: true,
    });

    await expect(
      service.signIn({
        email: testEmail,
        password: testPassword,
        ip_address: '198.51.100.99',
        user_agent: 'TorBrowser/12.0',
      }),
    ).rejects.toThrow(HighRiskSignInBlockedError);
  });
});

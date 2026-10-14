import { describe, it, expect, beforeEach } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { MockBreachedPasswordAdapter } from '../../src/infra/adapters/security/mock-pwned-passwords.adapter';

describe('Multi-Device Session Management & Remote Kill (OWASP ASVS 3.3)', () => {
  let router: AuthRestV1Router;
  let service: AuthService;
  let repo: AlloyDBOmniAuthAdapter;
  let userToken: string;
  let userId: string;
  let device1FamilyId: string;
  let device2FamilyId: string;
  let device3FamilyId: string;

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

    const userEmail = `multidevice_${Date.now()}@enterprise.com`;
    const signUpRes = await router.route('POST', '/api/v1/auth/sign-up', {
      email: userEmail,
      password: 'StrongSessionPass123!',
      name: 'Bob MultiDevice',
      organization_name: 'Sessions Inc',
    });
    userToken = (signUpRes.payload.data as any).token;
    userId = (signUpRes.payload.data as any).user.id;

    // Simulate 3 distinct client devices authenticating via RefreshTokenService
    const dev1 = await service.refreshTokenService.issueInitialRefreshToken(
      userId,
      '192.168.1.10',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X) Desktop'
    );
    device1FamilyId = dev1.familyId;

    const dev2 = await service.refreshTokenService.issueInitialRefreshToken(
      userId,
      '10.0.0.5',
      'Mozilla/5.0 (iPhone; CPU iPhone OS) Mobile'
    );
    device2FamilyId = dev2.familyId;

    const dev3 = await service.refreshTokenService.issueInitialRefreshToken(
      userId,
      '172.16.0.42',
      'Mozilla/5.0 (X11; Linux x86_64) Workstation'
    );
    device3FamilyId = dev3.familyId;
  });

  it('rejects unauthenticated requests to list sessions (401 Unauthorized)', async () => {
    const res = await router.route('GET', '/api/v1/auth/sessions');
    expect(res.statusCode).toBe(401);
    expect(res.payload.status).toBe('error');
    expect(res.payload.error?.code).toBe('UNAUTHORIZED');
  });

  it('enumerates all active concurrent sessions and correctly flags is_current for caller device', async () => {
    const res = await router.route(
      'GET',
      '/api/v1/auth/sessions',
      undefined,
      {
        authorization: `Bearer ${userToken}`,
        'x-session-family': device1FamilyId,
      }
    );

    expect(res.statusCode).toBe(200);
    expect(res.payload.status).toBe('success');
    const sessions = res.payload.data as any[];
    expect(sessions.length).toBe(3);

    const currentSession = sessions.find((s) => s.id === device1FamilyId);
    expect(currentSession).toBeDefined();
    expect(currentSession.is_current).toBe(true);
    expect(currentSession.ip_address).toBe('192.168.1.10');
    expect(currentSession.user_agent).toContain('Macintosh');

    const remotePhone = sessions.find((s) => s.id === device2FamilyId);
    expect(remotePhone).toBeDefined();
    expect(remotePhone.is_current).toBe(false);
    expect(remotePhone.ip_address).toBe('10.0.0.5');

    const remoteWorkstation = sessions.find((s) => s.id === device3FamilyId);
    expect(remoteWorkstation).toBeDefined();
    expect(remoteWorkstation.is_current).toBe(false);
  });

  it('terminates a specific remote session by family id without affecting others', async () => {
    const killRes = await router.route(
      'DELETE',
      `/api/v1/auth/sessions/${device2FamilyId}`,
      undefined,
      {
        authorization: `Bearer ${userToken}`,
      }
    );

    expect(killRes.statusCode).toBe(200);
    expect(killRes.payload.data).toEqual({
      sessionId: device2FamilyId,
      terminated: true,
    });

    // Check remaining sessions
    const listRes = await router.route(
      'GET',
      '/api/v1/auth/sessions',
      undefined,
      {
        authorization: `Bearer ${userToken}`,
        'x-session-family': device1FamilyId,
      }
    );

    const remaining = listRes.payload.data as any[];
    expect(remaining.length).toBe(2);
    expect(remaining.some((s) => s.id === device2FamilyId)).toBe(false);
    expect(remaining.some((s) => s.id === device1FamilyId)).toBe(true);
    expect(remaining.some((s) => s.id === device3FamilyId)).toBe(true);
  });

  it('bulk terminates all other sessions while immunizing current caller session', async () => {
    const bulkRes = await router.route(
      'DELETE',
      '/api/v1/auth/sessions',
      undefined,
      {
        authorization: `Bearer ${userToken}`,
        'x-session-family': device1FamilyId,
      }
    );

    expect(bulkRes.statusCode).toBe(200);
    expect(bulkRes.payload.data).toEqual({
      revokedCount: 2,
    });

    // Verify only current session remains active
    const listRes = await router.route(
      'GET',
      '/api/v1/auth/sessions',
      undefined,
      {
        authorization: `Bearer ${userToken}`,
        'x-session-family': device1FamilyId,
      }
    );

    const remaining = listRes.payload.data as any[];
    expect(remaining.length).toBe(1);
    expect(remaining[0].id).toBe(device1FamilyId);
    expect(remaining[0].is_current).toBe(true);
  });

  it('rejects attempt to revoke another user session (cross-tenant security boundary)', async () => {
    // Register another user
    const otherUserRes = await router.route('POST', '/api/v1/auth/sign-up', {
      email: `other_${Date.now()}@attacker.com`,
      password: 'StrongAttackerPass123!',
      name: 'Eve Attacker',
      organization_name: 'Attacker Org',
    });
    const otherToken = (otherUserRes.payload.data as any).token;

    // Attacker tries to terminate device1 belonging to Bob
    const res = await router.route(
      'DELETE',
      `/api/v1/auth/sessions/${device1FamilyId}`,
      undefined,
      {
        authorization: `Bearer ${otherToken}`,
      }
    );

    expect(res.statusCode).toBe(404);
    expect(res.payload.status).toBe('error');
    expect(res.payload.error?.code).toBe('RESOURCE_NOT_FOUND');
  });
});

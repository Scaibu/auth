import { describe, it, expect, beforeAll } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AUTH_ENDPOINTS, HTTP_METHODS } from '../../src/shared/constants/endpoints';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';
import { hashPassword } from '../../src/shared/utils/argon2.util';

describe('Break Glass Emergency Access E2E REST API Tests', () => {
  let adapter: AlloyDBOmniAuthAdapter;
  let service: AuthService;
  let router: AuthRestV1Router;
  let sessionToken: string;

  beforeAll(async () => {
    adapter = new AlloyDBOmniAuthAdapter();
    service = new AuthService(adapter);
    router = new AuthRestV1Router(service);

    const e2eOrgId = 'org_e2e_bg';
    const e2eUserId = 'usr_e2e_bg';
    const e2eEmail = 'breakglass_operator@observability.io';
    const password = 'StrongP@ssw0rd!2026';

    await adapter.createOrganization({
      id: e2eOrgId,
      name: 'Emergency Ops Org',
      slug: 'emergency-ops-org',
    });

    await adapter.createUser({
      id: e2eUserId,
      email: e2eEmail,
      name: 'BreakGlass Operator',
      org_id: e2eOrgId,
      org_name: 'Emergency Ops Org',
      role: 'admin',
      blocked: false,
      user_permissions: ['admin:all'],
      password_hash: await hashPassword(password),
    });

    const loginRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_IN, {
      email: e2eEmail,
      password,
    });
    sessionToken = (loginRes.payload.data as any).token;
  });

  it('activates emergency break-glass session via POST /api/v1/auth/break-glass/activate', async () => {
    const stepUpRes = await router.route(
      HTTP_METHODS.POST,
      '/api/v1/auth/step-up/verify',
      { password: 'StrongP@ssw0rd!2026' },
      { authorization: `Bearer ${sessionToken}` }
    );
    const reauthToken = (stepUpRes.payload.data as any).reauthToken;

    const res = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.BREAK_GLASS_ACTIVATE,
      {
        incident_ticket_id: 'INC-4040',
        justification: 'Emergency database connection pool saturation mitigation',
        duration_minutes: 60,
      },
      {
        authorization: `Bearer ${sessionToken}`,
        'x-reauth-token': reauthToken,
      }
    );

    expect(res.statusCode).toBe(200);
    const data = res.payload.data as any;
    expect(data.session.id).toMatch(/^bg_/);
    expect(data.session.status).toBe('ACTIVATED');
    expect(data.session.incident_ticket_id).toBe('INC-4040');
    expect(data.plaintextSecret.startsWith(AUTH_CONSTANTS.BREAK_GLASS.TOKEN_PREFIX)).toBe(true);

    const activeList = await router.route(
      HTTP_METHODS.GET,
      AUTH_ENDPOINTS.BREAK_GLASS_ACTIVE,
      undefined,
      {
        authorization: `Bearer ${sessionToken}`,
      }
    );
    expect(activeList.statusCode).toBe(200);
    expect((activeList.payload.data as any).length).toBe(1);

    const termRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.BREAK_GLASS_TERMINATE.replace(':id', data.session.id),
      {
        reason: 'Connection pool re-established and healthy',
      },
      {
        authorization: `Bearer ${sessionToken}`,
        'x-reauth-token': reauthToken,
      }
    );
    expect(termRes.statusCode).toBe(200);
    expect((termRes.payload.data as any).status).toBe('TERMINATED');
  });

  it('rejects break-glass activation without authentication or ticket id', async () => {
    const unauthRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.BREAK_GLASS_ACTIVATE,
      {
        incident_ticket_id: 'INC-5555',
        justification: 'Unauthenticated emergency call attempt',
      }
    );
    expect(unauthRes.statusCode).toBe(401);

    const stepUpRes = await router.route(
      HTTP_METHODS.POST,
      '/api/v1/auth/step-up/verify',
      { password: 'StrongP@ssw0rd!2026' },
      { authorization: `Bearer ${sessionToken}` }
    );
    const reauthToken = (stepUpRes.payload.data as any).reauthToken;

    const invalidRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.BREAK_GLASS_ACTIVATE,
      {
        incident_ticket_id: '',
        justification: 'Empty ticket',
      },
      {
        authorization: `Bearer ${sessionToken}`,
        'x-reauth-token': reauthToken,
      }
    );
    expect(invalidRes.statusCode).toBe(400);
  });
});

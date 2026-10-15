import { describe, it, expect, beforeAll } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { HTTP_METHODS, AUTH_ENDPOINTS } from '../../src/shared/constants/endpoints';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';
import { hashPassword } from '../../src/shared/utils/argon2.util';

describe('Custom Roles & 64-Bit Bitmasks E2E Flow', () => {
  let adapter: AlloyDBOmniAuthAdapter;
  let service: AuthService;
  let router: AuthRestV1Router;
  let adminToken: string;
  const e2eOrgId = 'org_e2e_custom_roles';
  const adminId = 'usr_admin_e2e_roles';
  const engineerId = 'usr_engineer_e2e_roles';
  const adminEmail = 'admin_roles@observability.io';

  beforeAll(async () => {
    adapter = new AlloyDBOmniAuthAdapter();
    service = new AuthService(adapter);
    router = new AuthRestV1Router(service);

    await adapter.createOrganization({
      id: e2eOrgId,
      name: 'E2E Custom Roles Org',
      slug: 'e2e-roles-org',
    });

    await adapter.createUser({
      id: adminId,
      email: adminEmail,
      name: 'Roles Admin',
      org_id: e2eOrgId,
      org_name: 'E2E Custom Roles Org',
      role: 'admin',
      blocked: false,
      user_permissions: ['admin:all'],
      password_hash: await hashPassword('AdminPass123!'),
    });

    await adapter.createUser({
      id: engineerId,
      email: 'engineer@observability.io',
      name: 'DevOps Engineer',
      org_id: e2eOrgId,
      org_name: 'E2E Custom Roles Org',
      role: 'member',
      blocked: false,
      user_permissions: [],
      password_hash: await hashPassword('EngineerPass123!'),
    });

    const loginRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_IN, {
      email: adminEmail,
      password: 'AdminPass123!',
    });
    adminToken = (loginRes.payload.data as any).token;
  });

  it('executes full custom role creation, user binding, and bitmask authorization verification', async () => {
    const sreMask = (
      BigInt(AUTH_CONSTANTS.PERMISSIONS_BITMASK.TELEMETRY_READ) |
      BigInt(AUTH_CONSTANTS.PERMISSIONS_BITMASK.TELEMETRY_WRITE)
    ).toString();

    const headers = { authorization: `Bearer ${adminToken}` };

    const createRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.ROLES,
      {
        name: 'DevOps Lead',
        description: 'Read and write telemetry data',
        permission_mask: sreMask,
      },
      headers
    );

    expect(createRes.statusCode).toBe(201);
    expect(createRes.payload.status).toBe('success');
    const createdRole = createRes.payload.data as any;
    expect(createdRole.id).toBeDefined();
    expect(createdRole.name).toBe('DevOps Lead');

    const listRes = await router.route(
      HTTP_METHODS.GET,
      AUTH_ENDPOINTS.ROLES,
      undefined,
      headers
    );

    expect(listRes.statusCode).toBe(200);
    const rolesList = listRes.payload.data as any[];
    expect(Array.isArray(rolesList)).toBe(true);
    expect(rolesList.some((r: any) => r.id === createdRole.id)).toBe(true);

    const assignUrl = AUTH_ENDPOINTS.USER_ROLES.replace(':userId', engineerId);
    const assignRes = await router.route(
      HTTP_METHODS.POST,
      assignUrl,
      { role_ids: [createdRole.id] },
      headers
    );

    expect(assignRes.statusCode).toBe(200);
    expect(assignRes.payload.status).toBe('success');

    const evalGrantedRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.PERMISSIONS_EVALUATE,
      {
        user_id: engineerId,
        org_id: e2eOrgId,
        required_permissions: ['TELEMETRY_READ', 'TELEMETRY_WRITE'],
      }
    );

    expect(evalGrantedRes.statusCode).toBe(200);
    const evalData = evalGrantedRes.payload.data as any;
    expect(evalData.granted).toBe(true);
    expect(evalData.missing_bits).toBe('0');

    const evalDeniedRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.PERMISSIONS_EVALUATE,
      {
        user_id: engineerId,
        org_id: e2eOrgId,
        required_permissions: ['TELEMETRY_READ', 'ORG_DELETE'],
      }
    );

    expect(evalDeniedRes.statusCode).toBe(200);
    const deniedData = evalDeniedRes.payload.data as any;
    expect(deniedData.granted).toBe(false);
    expect(BigInt(deniedData.missing_bits)).toBe(BigInt(AUTH_CONSTANTS.PERMISSIONS_BITMASK.ORG_DELETE));
  });
});

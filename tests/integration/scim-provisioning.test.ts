import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'crypto';
import { AuthService } from '../../src/features/auth/service';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AUTH_ENDPOINTS, HTTP_METHODS } from '../../src/shared/constants/endpoints';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('SCIM 2.0 User & Group Provisioning API (ADR 0024 / RFC 7643 & RFC 7644)', () => {
  let router: AuthRestV1Router;
  let repo: AlloyDBOmniAuthAdapter;
  let service: AuthService;
  const rawScimToken = 'scim_sec_super_secret_test_token_12345';
  const orgId = AUTH_CONSTANTS.DEFAULT_ORG_ID;

  beforeAll(async () => {
    repo = new AlloyDBOmniAuthAdapter();
    service = new AuthService(repo);
    router = new AuthRestV1Router(service);

    const tokenHash = createHash(AUTH_CONSTANTS.CRYPTO.ALGORITHM_SHA256)
      .update(rawScimToken)
      .digest(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX);

    await repo.saveScimToken({
      id: 'scim_tok_01',
      org_id: orgId,
      token_hash: tokenHash,
      description: 'Okta SCIM Integration Token',
      status: 'ACTIVE',
      created_at_ms: Date.now(),
      expires_at_ms: null,
      last_used_at_ms: null,
    });
  });

  it('GET /scim/v2/ServiceProviderConfig returns RFC 7643 capabilities without authentication', async () => {
    const res = await router.route(HTTP_METHODS.GET, AUTH_ENDPOINTS.SCIM_SERVICE_PROVIDER_CONFIG);
    expect(res.statusCode).toBe(200);
    expect((res.payload.data as any).schemas).toContain(AUTH_CONSTANTS.SCIM.SCHEMA_SERVICE_PROVIDER_CONFIG);
    expect((res.payload.data as any).patch.supported).toBe(true);
  });

  it('rejects SCIM requests without valid Bearer token', async () => {
    const res = await router.route(HTTP_METHODS.GET, AUTH_ENDPOINTS.SCIM_USERS);
    expect(res.statusCode).toBe(401);
  });

  it('provisions a new enterprise employee via POST /scim/v2/Users', async () => {
    const res = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.SCIM_USERS,
      {
        schemas: [AUTH_CONSTANTS.SCIM.SCHEMA_USER],
        userName: 'jane.scim@enterprise.com',
        externalId: 'okta_usr_9981',
        name: {
          formatted: 'Jane Doe',
          givenName: 'Jane',
          familyName: 'Doe',
        },
        emails: [{ value: 'jane.scim@enterprise.com', primary: true, type: 'work' }],
        active: true,
      },
      { authorization: `Bearer ${rawScimToken}` }
    );

    expect(res.statusCode).toBe(201);
    const data = res.payload.data as any;
    expect(data.id).toMatch(/^usr_/);
    expect(data.userName).toBe('jane.scim@enterprise.com');
    expect(data.name.formatted).toBe('Jane Doe');
    expect(data.active).toBe(true);
    expect(data.meta.resourceType).toBe('User');
  });

  it('queries user by userName filter via GET /scim/v2/Users?filter=userName eq "..."', async () => {
    const res = await router.route(
      HTTP_METHODS.GET,
      AUTH_ENDPOINTS.SCIM_USERS,
      undefined,
      { authorization: `Bearer ${rawScimToken}` },
      { filter: 'userName eq "jane.scim@enterprise.com"' }
    );

    expect(res.statusCode).toBe(200);
    const data = res.payload.data as any;
    expect(data.totalResults).toBe(1);
    expect(data.Resources[0].userName).toBe('jane.scim@enterprise.com');
  });

  it('deprovisions an employee via PATCH /scim/v2/Users/:id (active: false)', async () => {
    const listRes = await router.route(
      HTTP_METHODS.GET,
      AUTH_ENDPOINTS.SCIM_USERS,
      undefined,
      { authorization: `Bearer ${rawScimToken}` },
      { filter: 'userName eq "jane.scim@enterprise.com"' }
    );
    const userId = (listRes.payload.data as any).Resources[0].id;

    const patchRes = await router.route(
      HTTP_METHODS.PATCH,
      `/scim/v2/Users/${userId}`,
      {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [
          {
            op: 'replace',
            path: 'active',
            value: false,
          },
        ],
      },
      { authorization: `Bearer ${rawScimToken}` }
    );

    expect(patchRes.statusCode).toBe(200);
    expect((patchRes.payload.data as any).active).toBe(false);

    const userRecord = await repo.findUserById(userId);
    expect(userRecord?.blocked).toBe(true);
  });

  it('creates, queries, and manages groups via SCIM /scim/v2/Groups', async () => {
    const createGroupRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.SCIM_GROUPS,
      {
        schemas: [AUTH_CONSTANTS.SCIM.SCHEMA_GROUP],
        displayName: 'Platform Engineering',
        externalId: 'okta_grp_eng_01',
      },
      { authorization: `Bearer ${rawScimToken}` }
    );

    expect(createGroupRes.statusCode).toBe(201);
    const groupId = (createGroupRes.payload.data as any).id;
    expect(groupId).toMatch(/^grp_/);

    const getGroupRes = await router.route(
      HTTP_METHODS.GET,
      `/scim/v2/Groups/${groupId}`,
      undefined,
      { authorization: `Bearer ${rawScimToken}` }
    );
    expect(getGroupRes.statusCode).toBe(200);
    expect((getGroupRes.payload.data as any).displayName).toBe('Platform Engineering');
  });

});

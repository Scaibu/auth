import { describe, it, expect, beforeEach } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AUTH_ENDPOINTS, HTTP_METHODS } from '../../src/shared/constants/endpoints';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('Honeytoken REST Endpoints Integration (ADR 0041)', () => {
  let adapter: AlloyDBOmniAuthAdapter;
  let service: AuthService;
  let router: AuthRestV1Router;
  let adminAuthHeader: string;

  beforeEach(async () => {
    adapter = new AlloyDBOmniAuthAdapter();
    service = new AuthService(adapter as any);
    router = new AuthRestV1Router(service);

    const signUpResult = await service.signUp({
      email: 'honey_admin@observability.internal',
      password: 'AdminPassword123!',
      name: 'Honey Admin',
      organization_name: 'Honey Enterprise',
      role: AUTH_CONSTANTS.ROLE_ADMIN,
    });

    adminAuthHeader = `${AUTH_CONSTANTS.HEADERS.BEARER_PREFIX}${signUpResult.token}`;
  });

  it('provisions, lists, trips, and revokes honeytokens through the REST API layer', async () => {
    // 1. Create Honeytoken
    const createRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.HONEYTOKENS,
      {
        name: 'Staging Database Secret Trap',
        deployed_location: 's3://backups/staging.env',
      },
      {
        authorization: adminAuthHeader,
      }
    );

    expect(createRes.statusCode).toBe(201);
    expect(createRes.payload.status).toBe('success');
    const canary = createRes.payload.data as any;
    expect(canary.token).toMatch(/^ht_canary_/);
    expect(canary.name).toBe('Staging Database Secret Trap');

    // 2. List Honeytokens
    const listRes = await router.route(
      HTTP_METHODS.GET,
      AUTH_ENDPOINTS.HONEYTOKENS,
      undefined,
      {
        authorization: adminAuthHeader,
      }
    );

    expect(listRes.statusCode).toBe(200);
    const listData = listRes.payload.data as any[];
    expect(listData).toHaveLength(1);
    expect(listData[0].id).toBe(canary.id);

    // 3. Present Honeytoken on an authenticated endpoint -> triggers tripwire & returns 401
    const attackRes = await router.route(
      HTTP_METHODS.GET,
      AUTH_ENDPOINTS.USERS_ME,
      undefined,
      {
        authorization: `Bearer ${canary.token}`,
        'x-forwarded-for': '203.0.113.195',
        'user-agent': 'MaliciousScanner/2.4',
      }
    );

    expect(attackRes.statusCode).toBe(401);

    // 4. Inspect canary in DB -> tripwire count should be incremented and status changed to TRIPPED
    const listAfterAttack = await router.route(
      HTTP_METHODS.GET,
      AUTH_ENDPOINTS.HONEYTOKENS,
      undefined,
      {
        authorization: adminAuthHeader,
      }
    );

    const tripped = (listAfterAttack.payload.data as any[])[0];
    expect(tripped.tripwire_count).toBe(1);
    expect(tripped.status).toBe('TRIPPED');
    expect(tripped.last_tripped_ip).toBe('203.0.113.195');

    // 5. Revoke Honeytoken
    const revokeRes = await router.route(
      HTTP_METHODS.DELETE,
      `${AUTH_ENDPOINTS.HONEYTOKENS}/${canary.id}`,
      undefined,
      {
        authorization: adminAuthHeader,
      }
    );

    expect(revokeRes.statusCode).toBe(200);
    expect((revokeRes.payload.data as any).revoked).toBe(true);
  });
});

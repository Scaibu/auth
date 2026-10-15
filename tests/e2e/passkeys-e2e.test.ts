import { describe, it, expect, beforeAll } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { HTTP_METHODS, AUTH_ENDPOINTS } from '../../src/shared/constants/endpoints';
import { hashPassword } from '../../src/shared/utils/argon2.util';

describe('Passkeys End-to-End User Flow', () => {
  let adapter: AlloyDBOmniAuthAdapter;
  let service: AuthService;
  let router: AuthRestV1Router;
  let authToken: string;
  const e2eUserId = 'usr_e2e_passkey';
  const e2eOrgId = 'org_e2e_passkey';
  const e2eEmail = 'e2e_passkey@observability.io';

  beforeAll(async () => {
    adapter = new AlloyDBOmniAuthAdapter();
    service = new AuthService(adapter);
    router = new AuthRestV1Router(service);

    await adapter.createOrganization({
      id: e2eOrgId,
      name: 'E2E Passkey Org',
      slug: 'e2e-passkey-org',
    });

    await adapter.createUser({
      id: e2eUserId,
      email: e2eEmail,
      name: 'E2E Passkey User',
      org_id: e2eOrgId,
      org_name: 'E2E Passkey Org',
      role: 'admin',
      blocked: false,
      user_permissions: ['admin:all'],
      password_hash: await hashPassword('InitialPass123!'),
    });

    const loginRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_IN, {
      email: e2eEmail,
      password: 'InitialPass123!',
    });
    authToken = (loginRes.payload.data as any).token;
  });

  it('executes full passwordless lifecycle: register passkey -> sign in without password -> list -> delete', async () => {
    const regStart = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.PASSKEYS_REGISTER_START,
      {},
      { authorization: `Bearer ${authToken}` }
    );
    expect(regStart.statusCode).toBe(200);
    const regChallenge = regStart.payload.data as any;

    const clientDataJSONReg = Buffer.from(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: regChallenge.challenge,
        origin: 'http://localhost:3001',
      })
    ).toString('base64url');

    const regFinish = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.PASSKEYS_REGISTER_FINISH,
      {
        challenge_id: regChallenge.challenge_id,
        credential: {
          id: 'cred_e2e_hardware_key',
          type: 'public-key',
          response: {
            clientDataJSON: clientDataJSONReg,
            attestationObject: 'mock_attestation_bytes',
            transports: ['usb', 'nfc'],
          },
        },
        friendly_name: 'Primary YubiKey',
      },
      { authorization: `Bearer ${authToken}` }
    );
    expect(regFinish.statusCode).toBe(201);
    const registered = regFinish.payload.data as any;
    expect(registered.credential_id).toBe('cred_e2e_hardware_key');

    const authStart = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.PASSKEYS_AUTHENTICATE_START,
      { email: e2eEmail }
    );
    expect(authStart.statusCode).toBe(200);
    const authChallenge = authStart.payload.data as any;

    const clientDataJSONAuth = Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: authChallenge.challenge,
        origin: 'http://localhost:3001',
      })
    ).toString('base64url');

    const authDataBuf = Buffer.alloc(37);
    authDataBuf.writeUInt32BE(10, 33);

    const authFinish = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.PASSKEYS_AUTHENTICATE_FINISH,
      {
        challenge_id: authChallenge.challenge_id,
        credential: {
          id: 'cred_e2e_hardware_key',
          type: 'public-key',
          response: {
            clientDataJSON: clientDataJSONAuth,
            authenticatorData: authDataBuf.toString('base64url'),
            signature: 'valid_mock_signature',
          },
        },
      }
    );
    expect(authFinish.statusCode).toBe(200);
    const sessionData = authFinish.payload.data as any;
    expect(sessionData.token).toBeDefined();
    expect(sessionData.user.id).toBe(e2eUserId);

    const newAuthToken = sessionData.token;
    const listRes = await router.route(
      HTTP_METHODS.GET,
      AUTH_ENDPOINTS.PASSKEYS_LIST,
      {},
      { authorization: `Bearer ${newAuthToken}` }
    );
    expect(listRes.statusCode).toBe(200);
    const keys = listRes.payload.data as any[];
    expect(keys.length).toBe(1);

    const deleteRes = await router.route(
      HTTP_METHODS.DELETE,
      AUTH_ENDPOINTS.PASSKEYS_DELETE.replace(':id', keys[0].id),
      {},
      { authorization: `Bearer ${newAuthToken}` }
    );
    expect(deleteRes.statusCode).toBe(200);

    const listAfterDelete = await router.route(
      HTTP_METHODS.GET,
      AUTH_ENDPOINTS.PASSKEYS_LIST,
      {},
      { authorization: `Bearer ${newAuthToken}` }
    );
    expect((listAfterDelete.payload.data as any[]).length).toBe(0);
  });
});

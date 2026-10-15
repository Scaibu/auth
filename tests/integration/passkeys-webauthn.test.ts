import { describe, it, expect, beforeEach } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { RealPostgresAuthAdapter } from '../../src/infra/adapters/postgres/real-postgres-auth.adapter';
import { HTTP_METHODS, AUTH_ENDPOINTS } from '../../src/shared/constants/endpoints';
import { AUTH_CONFIG } from '../../src/config/env.config';
import { hashPassword } from '../../src/shared/utils/argon2.util';

describe('W3C WebAuthn Level 3 & FIDO2 Passkeys Verification', () => {
  let adapter: AlloyDBOmniAuthAdapter;
  let service: AuthService;
  let router: AuthRestV1Router;
  let authToken: string;
  const testUserId = 'usr_passkey_test';
  const testOrgId = 'org_passkey_test';
  const testEmail = 'passkey_user@observability.io';

  beforeEach(async () => {
    adapter = new AlloyDBOmniAuthAdapter();
    service = new AuthService(adapter);
    router = new AuthRestV1Router(service);

    await adapter.createOrganization({
      id: testOrgId,
      name: 'Passkey Test Org',
      slug: 'passkey-test-org',
    });

    await adapter.createUser({
      id: testUserId,
      email: testEmail,
      name: 'Passkey Test User',
      org_id: testOrgId,
      org_name: 'Passkey Test Org',
      role: 'admin',
      blocked: false,
      user_permissions: ['admin:all'],
      password_hash: await hashPassword('ValidPass123!'),
    });

    const signInRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_IN, {
      email: testEmail,
      password: 'ValidPass123!',
    });
    authToken = (signInRes.payload.data as any).token;
  });

  it('1. Generates WebAuthn registration options with secure challenge', async () => {
    const res = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.PASSKEYS_REGISTER_START,
      {},
      { authorization: `Bearer ${authToken}` }
    );

    expect(res.statusCode).toBe(200);
    const data = res.payload.data as any;
    expect(data.challenge).toBeDefined();
    expect(data.challenge_id).toBeDefined();
    expect(data.rp.id).toBeDefined();
    expect(data.user.name).toBe(testEmail);
  });

  it('2. Completes passkey registration and persists credential', async () => {
    const startRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.PASSKEYS_REGISTER_START,
      {},
      { authorization: `Bearer ${authToken}` }
    );
    const challengeData = startRes.payload.data as any;

    const clientDataJSON = Buffer.from(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: challengeData.challenge,
        origin: 'http://localhost:3001',
      })
    ).toString('base64url');

    const finishRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.PASSKEYS_REGISTER_FINISH,
      {
        challenge_id: challengeData.challenge_id,
        credential: {
          id: 'cred_raw_key_123',
          type: 'public-key',
          response: {
            clientDataJSON,
            attestationObject: 'dummy_attestation_object_base64',
            transports: ['internal', 'hybrid'],
          },
        },
        friendly_name: 'MacBook TouchID',
      },
      { authorization: `Bearer ${authToken}` }
    );

    expect(finishRes.statusCode).toBe(201);
    const saved = finishRes.payload.data as any;
    expect(saved.credential_id).toBe('cred_raw_key_123');
    expect(saved.friendly_name).toBe('MacBook TouchID');

    const listRes = await router.route(
      HTTP_METHODS.GET,
      AUTH_ENDPOINTS.PASSKEYS_LIST,
      {},
      { authorization: `Bearer ${authToken}` }
    );
    expect(listRes.statusCode).toBe(200);
    const list = listRes.payload.data as any[];
    expect(list.length).toBe(1);
    expect(list[0].credential_id).toBe('cred_raw_key_123');
  });

  it('3. Authenticates seamlessly via registered passkey', async () => {
    const startRegRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.PASSKEYS_REGISTER_START,
      {},
      { authorization: `Bearer ${authToken}` }
    );
    const regData = startRegRes.payload.data as any;

    const clientDataJSONReg = Buffer.from(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: regData.challenge,
        origin: 'http://localhost:3001',
      })
    ).toString('base64url');

    await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.PASSKEYS_REGISTER_FINISH,
      {
        challenge_id: regData.challenge_id,
        credential: {
          id: 'cred_touch_id_test',
          type: 'public-key',
          response: {
            clientDataJSON: clientDataJSONReg,
            attestationObject: 'mock_attestation_data',
          },
        },
      },
      { authorization: `Bearer ${authToken}` }
    );

    const authStartRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.PASSKEYS_AUTHENTICATE_START,
      { email: testEmail }
    );
    expect(authStartRes.statusCode).toBe(200);
    const authStartData = authStartRes.payload.data as any;
    expect(authStartData.allowCredentials?.length).toBe(1);

    const clientDataJSONAuth = Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: authStartData.challenge,
        origin: 'http://localhost:3001',
      })
    ).toString('base64url');

    const authDataBuf = Buffer.alloc(37);
    authDataBuf.writeUInt32BE(1, 33);
    const authDataStr = authDataBuf.toString('base64url');

    const authFinishRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.PASSKEYS_AUTHENTICATE_FINISH,
      {
        challenge_id: authStartData.challenge_id,
        credential: {
          id: 'cred_touch_id_test',
          type: 'public-key',
          response: {
            clientDataJSON: clientDataJSONAuth,
            authenticatorData: authDataStr,
            signature: 'dummy_signature_sig',
          },
        },
      }
    );

    expect(authFinishRes.statusCode).toBe(200);
    const authResult = authFinishRes.payload.data as any;
    expect(authResult.token).toBeDefined();
    expect(authResult.user.email).toBe(testEmail);
  });

  it('4. Rejects cloned passkey if sign counter rolls back', async () => {
    const startRegRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.PASSKEYS_REGISTER_START,
      {},
      { authorization: `Bearer ${authToken}` }
    );
    const regData = startRegRes.payload.data as any;

    const clientDataJSONReg = Buffer.from(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: regData.challenge,
        origin: 'http://localhost:3001',
      })
    ).toString('base64url');

    await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.PASSKEYS_REGISTER_FINISH,
      {
        challenge_id: regData.challenge_id,
        credential: {
          id: 'cred_clone_test',
          type: 'public-key',
          response: {
            clientDataJSON: clientDataJSONReg,
            attestationObject: 'mock_attestation_data',
          },
        },
      },
      { authorization: `Bearer ${authToken}` }
    );

    const authStartRes1 = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.PASSKEYS_AUTHENTICATE_START,
      { email: testEmail }
    );
    const authStartData1 = authStartRes1.payload.data as any;

    const authDataBufHigh = Buffer.alloc(37);
    authDataBufHigh.writeUInt32BE(50, 33);

    await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.PASSKEYS_AUTHENTICATE_FINISH,
      {
        challenge_id: authStartData1.challenge_id,
        credential: {
          id: 'cred_clone_test',
          type: 'public-key',
          response: {
            clientDataJSON: Buffer.from(
              JSON.stringify({
                type: 'webauthn.get',
                challenge: authStartData1.challenge,
                origin: 'http://localhost:3001',
              })
            ).toString('base64url'),
            authenticatorData: authDataBufHigh.toString('base64url'),
            signature: 'dummy_sig',
          },
        },
      }
    );

    const authStartRes2 = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.PASSKEYS_AUTHENTICATE_START,
      { email: testEmail }
    );
    const authStartData2 = authStartRes2.payload.data as any;

    const authDataBufLow = Buffer.alloc(37);
    authDataBufLow.writeUInt32BE(40, 33);

    const cloneRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.PASSKEYS_AUTHENTICATE_FINISH,
      {
        challenge_id: authStartData2.challenge_id,
        credential: {
          id: 'cred_clone_test',
          type: 'public-key',
          response: {
            clientDataJSON: Buffer.from(
              JSON.stringify({
                type: 'webauthn.get',
                challenge: authStartData2.challenge,
                origin: 'http://localhost:3001',
              })
            ).toString('base64url'),
            authenticatorData: authDataBufLow.toString('base64url'),
            signature: 'dummy_sig',
          },
        },
      }
    );

    expect(cloneRes.statusCode).toBe(401);
  });

  it('5. Real PostgreSQL / AlloyDB Omni Passkey persistence and query execution', async () => {
    const realAdapter = new RealPostgresAuthAdapter(AUTH_CONFIG.db.url);
    const pgUserId = `usr_pg_passkey_${Date.now()}`;
    const pgOrgId = `org_pg_passkey_${Date.now()}`;

    try {
      await realAdapter.createOrganizationAndUser({
        id: pgUserId,
        email: `pg_passkey_${Date.now()}@observability.io`,
        password_hash: await hashPassword('InitialPass123!'),
        name: 'PG Passkey User',
        org_id: pgOrgId,
        org_name: `PG Passkey Org ${Date.now()}`,
        role: 'admin',
        blocked: false,
        user_permissions: ['admin:all'],
      });

      const challengeId = `chal_pg_${Date.now()}`;
      await realAdapter.savePasskeyChallenge({
        challenge_id: challengeId,
        user_id: pgUserId,
        challenge: 'pg_challenge_random_string',
        origin: 'http://localhost:3001',
        rp_id: 'localhost',
        challenge_type: 'registration',
        expires_at_ms: Date.now() + 60000,
        created_at_ms: Date.now(),
      });

      const foundChallenge = await realAdapter.findPasskeyChallenge(challengeId);
      expect(foundChallenge).not.toBeNull();
      expect(foundChallenge?.challenge_id).toBe(challengeId);

      await realAdapter.consumePasskeyChallenge(challengeId);
      const afterConsume = await realAdapter.findPasskeyChallenge(challengeId);
      expect(afterConsume).toBeNull();

      const credId = `cred_id_pg_${Date.now()}`;
      await realAdapter.savePasskeyCredential({
        id: `pk_${Date.now()}`,
        credential_id: credId,
        user_id: pgUserId,
        org_id: pgOrgId,
        public_key: 'pg_dummy_public_key',
        counter: 0,
        device_type: 'single_device',
        backed_up: false,
        transports: ['internal'],
        friendly_name: 'YubiKey 5C NFC',
        created_at_ms: Date.now(),
      });

      const foundCred = await realAdapter.findPasskeyCredentialById(credId);
      expect(foundCred).not.toBeNull();
      expect(foundCred?.friendly_name).toBe('YubiKey 5C NFC');

      await realAdapter.updatePasskeyCounter(credId, 1, Date.now());
      const updatedCred = await realAdapter.findPasskeyCredentialById(credId);
      expect(updatedCred?.counter).toBe(1);

      const userPasskeys = await realAdapter.listPasskeysByUserId(pgUserId);
      expect(userPasskeys.length).toBe(1);

      await realAdapter.deletePasskey(foundCred!.id, pgUserId);
      const afterDelete = await realAdapter.findPasskeyCredentialById(credId);
      expect(afterDelete).toBeNull();
    } finally {
      await realAdapter.close();
    }
  });
});

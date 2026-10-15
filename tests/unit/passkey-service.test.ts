import { describe, it, expect, beforeEach } from 'vitest';
import { PasskeyService } from '../../src/features/auth/services/passkey.service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { ValidationError, UnauthorizedError, ConflictError } from '../../src/shared/errors/auth.errors';

describe('PasskeyService Unit Tests', () => {
  let adapter: AlloyDBOmniAuthAdapter;
  let service: PasskeyService;
  const userId = 'usr_unit_test';
  const orgId = 'org_unit_test';
  const email = 'unit_passkey@observability.io';

  beforeEach(() => {
    adapter = new AlloyDBOmniAuthAdapter();
    service = new PasskeyService(adapter);
  });

  it('generates registration options with high-entropy challenge and correct RP parameters', async () => {
    const opts = await service.generateRegistrationOptions(userId, email, 'Unit Test User');
    expect(opts.challenge).toBeDefined();
    expect(opts.challenge.length).toBeGreaterThan(20);
    expect(opts.rp.name).toBe('Observability Cloud');
    expect(opts.user.name).toBe(email);
    expect(opts.attestation).toBe('none');

    const stored = await adapter.findPasskeyChallenge(opts.challenge_id);
    expect(stored).not.toBeNull();
    expect(stored?.user_id).toBe(userId);
  });

  it('rejects registration finish if challenge is expired or invalid', async () => {
    await expect(
      service.verifyRegistrationResponse(userId, orgId, {
        challenge_id: 'non_existent_challenge',
        credential: {
          id: 'cred_123',
          type: 'public-key',
          response: {
            clientDataJSON: Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: 'xyz', origin: 'http://localhost:3001' })).toString('base64url'),
            attestationObject: 'mock_attestation',
          },
        },
      })
    ).rejects.toThrow(ValidationError);
  });

  it('rejects registration finish if clientDataJSON contains invalid type', async () => {
    const opts = await service.generateRegistrationOptions(userId, email, 'Unit Test User');
    const invalidClientData = Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: opts.challenge,
        origin: 'http://localhost:3001',
      })
    ).toString('base64url');

    await expect(
      service.verifyRegistrationResponse(userId, orgId, {
        challenge_id: opts.challenge_id,
        credential: {
          id: 'cred_123',
          type: 'public-key',
          response: {
            clientDataJSON: invalidClientData,
            attestationObject: 'mock_attestation',
          },
        },
      })
    ).rejects.toThrow(ValidationError);
  });

  it('successfully persists passkey and enforces unique credential ID', async () => {
    const opts = await service.generateRegistrationOptions(userId, email, 'Unit Test User');
    const validClientData = Buffer.from(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: opts.challenge,
        origin: 'http://localhost:3001',
      })
    ).toString('base64url');

    const cred = await service.verifyRegistrationResponse(userId, orgId, {
      challenge_id: opts.challenge_id,
      credential: {
        id: 'cred_unique_test',
        type: 'public-key',
        response: {
          clientDataJSON: validClientData,
          attestationObject: 'mock_attestation',
        },
      },
    });

    expect(cred.credential_id).toBe('cred_unique_test');

    const opts2 = await service.generateRegistrationOptions(userId, email, 'Unit Test User');
    const validClientData2 = Buffer.from(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: opts2.challenge,
        origin: 'http://localhost:3001',
      })
    ).toString('base64url');

    await expect(
      service.verifyRegistrationResponse(userId, orgId, {
        challenge_id: opts2.challenge_id,
        credential: {
          id: 'cred_unique_test',
          type: 'public-key',
          response: {
            clientDataJSON: validClientData2,
            attestationObject: 'mock_attestation',
          },
        },
      })
    ).rejects.toThrow(ConflictError);
  });

  it('rejects authentication with unknown credential ID', async () => {
    const opts = await service.generateAuthenticationOptions();
    const clientData = Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: opts.challenge,
        origin: 'http://localhost:3001',
      })
    ).toString('base64url');

    const authDataBuf = Buffer.alloc(37);
    authDataBuf.writeUInt32BE(1, 33);

    await expect(
      service.verifyAuthenticationResponse({
        challenge_id: opts.challenge_id,
        credential: {
          id: 'unknown_cred_id',
          type: 'public-key',
          response: {
            clientDataJSON: clientData,
            authenticatorData: authDataBuf.toString('base64url'),
            signature: 'sig',
          },
        },
      })
    ).rejects.toThrow(UnauthorizedError);
  });
});

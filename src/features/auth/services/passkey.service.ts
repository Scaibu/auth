import * as crypto from 'crypto';
import type { AuthRepositoryPort } from '../repository';
import type { PasskeyCredentialRecord } from '../../../shared/types/auth.types';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { ValidationError, UnauthorizedError, ConflictError } from '../../../shared/errors/auth.errors';
import { withSpan } from '../../../infra/tracing/tracer';

export interface PasskeyRegistrationOptions {
  challenge: string;
  challenge_id: string;
  rp: {
    name: string;
    id: string;
  };
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  pubKeyCredParams: Array<{ alg: number; type: 'public-key' }>;
  timeout: number;
  attestation: 'none';
  authenticatorSelection: {
    residentKey: 'preferred';
    userVerification: 'preferred';
  };
}

export interface PasskeyAuthenticationOptions {
  challenge: string;
  challenge_id: string;
  rpId: string;
  timeout: number;
  userVerification: 'preferred';
  allowCredentials?: Array<{ id: string; type: 'public-key'; transports?: string[] }>;
}

export class PasskeyService {
  constructor(private readonly repository: AuthRepositoryPort) {}

  async generateRegistrationOptions(userId: string, email: string, name: string): Promise<PasskeyRegistrationOptions> {
    return withSpan('PasskeyService.generateRegistrationOptions', async () => {
      const challenge = crypto.randomBytes(32).toString('base64url');
      const challengeId = `chal_${crypto.randomUUID()}`;
      const now = Date.now();

      await this.repository.savePasskeyChallenge({
        challenge_id: challengeId,
        user_id: userId,
        challenge,
        origin: AUTH_CONSTANTS.WEBAUTHN.ORIGIN,
        rp_id: AUTH_CONSTANTS.WEBAUTHN.RP_ID,
        challenge_type: 'registration',
        expires_at_ms: now + AUTH_CONSTANTS.WEBAUTHN.CHALLENGE_TTL_MS,
        created_at_ms: now,
      });

      return {
        challenge,
        challenge_id: challengeId,
        rp: {
          name: AUTH_CONSTANTS.WEBAUTHN.RP_NAME,
          id: AUTH_CONSTANTS.WEBAUTHN.RP_ID,
        },
        user: {
          id: Buffer.from(userId).toString('base64url'),
          name: email,
          displayName: name,
        },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' },
          { alg: -257, type: 'public-key' },
        ],
        timeout: 60000,
        attestation: 'none',
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: 'preferred',
        },
      };
    });
  }

  async verifyRegistrationResponse(
    userId: string,
    orgId: string,
    params: {
      challenge_id: string;
      credential: {
        id: string;
        response: {
          clientDataJSON: string;
          attestationObject: string;
          transports?: string[];
        };
        type: 'public-key';
      };
      friendly_name?: string;
    }
  ): Promise<PasskeyCredentialRecord> {
    return withSpan('PasskeyService.verifyRegistrationResponse', async () => {
      const storedChallenge = await this.repository.findPasskeyChallenge(params.challenge_id);
      if (!storedChallenge || storedChallenge.challenge_type !== 'registration' || storedChallenge.user_id !== userId) {
        throw new ValidationError('Invalid or expired registration challenge');
      }

      await this.repository.consumePasskeyChallenge(params.challenge_id);

      const clientDataRaw = Buffer.from(params.credential.response.clientDataJSON, 'base64url').toString('utf8');
      let clientData: { type: string; challenge: string; origin: string };
      try {
        clientData = JSON.parse(clientDataRaw);
      } catch {
        throw new ValidationError('Malformed clientDataJSON');
      }

      if (clientData.type !== 'webauthn.create') {
        throw new ValidationError('Invalid clientData type for registration');
      }
      if (clientData.challenge !== storedChallenge.challenge) {
        throw new ValidationError('Challenge mismatch in registration');
      }

      const existingCred = await this.repository.findPasskeyCredentialById(params.credential.id);
      if (existingCred) {
        throw new ConflictError('Passkey credential already registered');
      }

      const id = `cred_${crypto.randomUUID()}`;
      const now = Date.now();
      const passkeyRecord: PasskeyCredentialRecord = {
        id,
        credential_id: params.credential.id,
        user_id: userId,
        org_id: orgId,
        public_key: params.credential.response.attestationObject,
        counter: 0,
        device_type: 'single_device',
        backed_up: false,
        transports: params.credential.response.transports ?? [],
        friendly_name: params.friendly_name ?? 'Passkey',
        created_at_ms: now,
      };

      await this.repository.savePasskeyCredential(passkeyRecord);
      return passkeyRecord;
    });
  }

  async generateAuthenticationOptions(userEmail?: string): Promise<PasskeyAuthenticationOptions> {
    return withSpan('PasskeyService.generateAuthenticationOptions', async () => {
      const challenge = crypto.randomBytes(32).toString('base64url');
      const challengeId = `chal_${crypto.randomUUID()}`;
      const now = Date.now();

      let targetUserId: string | null = null;
      let allowCredentials: Array<{ id: string; type: 'public-key'; transports?: string[] }> | undefined;

      if (userEmail) {
        const user = await this.repository.findUserByEmail(userEmail);
        if (user) {
          targetUserId = user.id;
          const userPasskeys = await this.repository.listPasskeysByUserId(user.id);
          allowCredentials = userPasskeys.map(p => ({
            id: p.credential_id,
            type: 'public-key',
            transports: p.transports,
          }));
        }
      }

      await this.repository.savePasskeyChallenge({
        challenge_id: challengeId,
        user_id: targetUserId,
        challenge,
        origin: AUTH_CONSTANTS.WEBAUTHN.ORIGIN,
        rp_id: AUTH_CONSTANTS.WEBAUTHN.RP_ID,
        challenge_type: 'authentication',
        expires_at_ms: now + AUTH_CONSTANTS.WEBAUTHN.CHALLENGE_TTL_MS,
        created_at_ms: now,
      });

      return {
        challenge,
        challenge_id: challengeId,
        rpId: AUTH_CONSTANTS.WEBAUTHN.RP_ID,
        timeout: 60000,
        userVerification: 'preferred',
        allowCredentials,
      };
    });
  }

  async verifyAuthenticationResponse(params: Readonly<{
    challenge_id: string;
    credential: Readonly<{
      id: string;
      response: Readonly<{
        clientDataJSON: string;
        authenticatorData: string;
        signature: string;
        userHandle?: string | null;
      }>;
      type: 'public-key';
    }>;
  }>): Promise<{ userId: string; credentialId: string }> {
    return withSpan('PasskeyService.verifyAuthenticationResponse', async (span: any) => {
      const storedChallenge = await this.repository.findPasskeyChallenge(params.challenge_id);
      if (!storedChallenge) {
        throw new ValidationError('Invalid or expired authentication challenge');
      }
      if (storedChallenge.challenge_type !== 'authentication') {
        throw new ValidationError('Invalid or expired authentication challenge');
      }

      await this.repository.consumePasskeyChallenge(params.challenge_id);

      const clientDataRaw = Buffer.from(params.credential.response.clientDataJSON, 'base64url').toString('utf8');
      let clientData: { type: string; challenge: string; origin: string };
      try {
        clientData = JSON.parse(clientDataRaw);
      } catch {
        throw new ValidationError('Malformed clientDataJSON');
      }

      if (clientData.type !== 'webauthn.get') {
        throw new ValidationError('Invalid clientData type for authentication');
      }
      if (clientData.challenge !== storedChallenge.challenge) {
        throw new ValidationError('Challenge mismatch in authentication');
      }

      const passkey = await this.repository.findPasskeyCredentialById(params.credential.id);
      if (!passkey) {
        throw new UnauthorizedError('Unknown passkey credential');
      }

      const challengedUserId = storedChallenge.user_id;
      if (challengedUserId !== null && challengedUserId !== undefined && challengedUserId !== passkey.user_id) {
        throw new UnauthorizedError('Passkey credential does not match challenged user');
      }

      const authDataBuf = Buffer.from(params.credential.response.authenticatorData, 'base64url');
      const signCount = authDataBuf.length >= 37 ? authDataBuf.readUInt32BE(33) : 0;

      const isCloneRollback = (signCount > 0) && (passkey.counter > 0) && (signCount <= passkey.counter);
      if (isCloneRollback) {
        span?.setAttribute('webauthn.clone_detected', true);
        throw new UnauthorizedError('Passkey clone detected: signature counter rollback');
      }

      const nextCounter = signCount > passkey.counter ? signCount : passkey.counter + 1;
      await this.repository.updatePasskeyCounter(passkey.credential_id, nextCounter, Date.now());

      return {
        userId: passkey.user_id,
        credentialId: passkey.credential_id,
      };
    });
  }

  async listUserPasskeys(userId: string) {
    return this.repository.listPasskeysByUserId(userId);
  }

  async deletePasskey(passkeyId: string, userId: string): Promise<void> {
    await this.repository.deletePasskey(passkeyId, userId);
  }
}

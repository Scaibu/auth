import { generateKeyPairSync, sign, verify, createSign, createHash, createPrivateKey, createPublicKey, KeyObject } from 'crypto';
import { withSpan } from '../../../infra/tracing/tracer';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { ValidationError, UnauthorizedError } from '../../../shared/errors/auth.errors';
import type { SigningKeyRecord, JwksKey, OidcRepositoryPort } from '../ports/oidc-repository.port';

export class KeyRotationService {
  private readonly privKeyObjectCache: Map<string, KeyObject> = new Map();
  private readonly pubKeyObjectCache: Map<string, KeyObject> = new Map();

  constructor(private readonly repo: OidcRepositoryPort) {}

  async getPublicJwks(): Promise<{ keys: ReadonlyArray<JwksKey> }> {
    return withSpan('KeyRotationService.getPublicJwks', async () => {
      await this.ensureActiveEdDsaKey();
      const keys = await this.repo.listPublicJwksKeys();
      return { keys };
    });
  }

  async ensureActiveEdDsaKey(): Promise<SigningKeyRecord> {
    return withSpan('KeyRotationService.ensureActiveEdDsaKey', async () => {
      let key = await this.repo.getActiveSigningKey(AUTH_CONSTANTS.OIDC.KEY_ALG_EDDSA);
      if (!key) {
        key = this.generateEd25519KeyRecord();
        await this.repo.saveSigningKey(key);
      }
      return key;
    });
  }

  async rotateKey(params?: {
    alg?: 'EdDSA' | 'RS256';
    gracePeriodMs?: number;
  }): Promise<{ newKey: SigningKeyRecord; gracePeriodMs: number }> {
    return withSpan('KeyRotationService.rotateKey', async () => {
      const alg = params?.alg || (AUTH_CONSTANTS.OIDC.KEY_ALG_EDDSA as 'EdDSA');
      const gracePeriodMs = params?.gracePeriodMs ?? AUTH_CONSTANTS.OIDC.DEFAULT_ROTATION_GRACE_PERIOD_MS;

      const newKey = alg === AUTH_CONSTANTS.OIDC.KEY_ALG_EDDSA
        ? this.generateEd25519KeyRecord()
        : this.generateRsaKeyRecord();

      await this.repo.rotateSigningKey(newKey, gracePeriodMs);
      return { newKey, gracePeriodMs };
    });
  }

  async revokeKey(kid: string, reason: string): Promise<void> {
    return withSpan('KeyRotationService.revokeKey', async () => {
      if (!kid || typeof kid !== 'string') {
        throw new ValidationError('Valid kid required for key revocation');
      }
      if (!reason || typeof reason !== 'string') {
        throw new ValidationError('Revocation reason is mandatory');
      }
      const existing = await this.repo.getSigningKeyByKid(kid);
      if (!existing) {
        throw new ValidationError(`Signing key not found: ${kid}`);
      }
      await this.repo.revokeSigningKey(kid, reason, Date.now());
      this.privKeyObjectCache.delete(kid);
      this.pubKeyObjectCache.delete(kid);
    });
  }

  signJwt(payload: Record<string, unknown>, key: SigningKeyRecord): string {
    const header = {
      alg: key.alg,
      typ: 'JWT',
      kid: key.kid,
    };
    const b64Header = Buffer.from(JSON.stringify(header)).toString('base64url');
    const b64Payload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signingInput = `${b64Header}.${b64Payload}`;

    if (key.alg === AUTH_CONSTANTS.OIDC.KEY_ALG_EDDSA) {
      let keyObj = this.privKeyObjectCache.get(key.kid);
      if (!keyObj) {
        keyObj = createPrivateKey(key.private_key_pem);
        this.privKeyObjectCache.set(key.kid, keyObj);
      }
      const signature = sign(null, Buffer.from(signingInput), keyObj).toString('base64url');
      return `${signingInput}.${signature}`;
    }

    const signer = createSign('RSA-SHA256');
    signer.update(signingInput);
    signer.end();
    const signature = signer.sign(key.private_key_pem).toString('base64url');
    return `${signingInput}.${signature}`;
  }

  async verifyJwt(token: string): Promise<{ header: Record<string, any>; payload: Record<string, any> }> {
    return withSpan('KeyRotationService.verifyJwt', async () => {
      if (!token || typeof token !== 'string') {
        throw new UnauthorizedError('Token is required');
      }
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new UnauthorizedError('Malformed JWT structure');
      }

      const [b64Header, b64Payload, b64Signature] = parts as [string, string, string];
      let header: Record<string, any>;
      let payload: Record<string, any>;

      try {
        header = JSON.parse(Buffer.from(b64Header, 'base64url').toString('utf8'));
        payload = JSON.parse(Buffer.from(b64Payload, 'base64url').toString('utf8'));
      } catch {
        throw new UnauthorizedError('Invalid JWT JSON encoding');
      }

      const kid = header.kid;
      if (!kid) {
        throw new UnauthorizedError('Missing kid in JWT header');
      }

      const key = await this.repo.getSigningKeyByKid(kid);
      if (!key) {
        throw new UnauthorizedError(`Unknown signing key: ${kid}`);
      }

      if (key.status === AUTH_CONSTANTS.OIDC.KEY_STATUS_REVOKED) {
        throw new UnauthorizedError(`Token signing key is revoked: ${kid}`);
      }

      if (key.status === AUTH_CONSTANTS.OIDC.KEY_STATUS_RETIRED) {
        const now = Date.now();
        if (key.expires_at_ms && key.expires_at_ms < now) {
          throw new UnauthorizedError(`Token signing key grace period expired: ${kid}`);
        }
      }

      const signingInput = Buffer.from(`${b64Header}.${b64Payload}`);
      const rawSignature = Buffer.from(b64Signature, 'base64url');

      if (key.alg === AUTH_CONSTANTS.OIDC.KEY_ALG_EDDSA) {
        let keyObj = this.pubKeyObjectCache.get(key.kid);
        if (!keyObj) {
          keyObj = createPublicKey(key.public_key_pem);
          this.pubKeyObjectCache.set(key.kid, keyObj);
        }
        const isValid = verify(null, signingInput, keyObj, rawSignature);
        if (!isValid) {
          throw new UnauthorizedError('Invalid cryptographic token signature');
        }
      } else {
        const isValid = verify('RSA-SHA256', signingInput, key.public_key_pem, rawSignature);
        if (!isValid) {
          throw new UnauthorizedError('Invalid cryptographic token signature');
        }
      }

      const nowSeconds = Math.floor(Date.now() / 1000);
      if (payload.exp && typeof payload.exp === 'number' && payload.exp < nowSeconds) {
        throw new UnauthorizedError('Token has expired');
      }

      return { header, payload };
    });
  }

  generateEd25519KeyRecord(): SigningKeyRecord {
    const pair = generateKeyPairSync('ed25519');
    const privateKeyPem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    const publicKeyPem = pair.publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const jwk = pair.publicKey.export({ format: 'jwk' });
    const now = Date.now();

    return {
      kid: `key_ed25519_${now}_${Math.random().toString(36).substring(2, 8)}`,
      kty: AUTH_CONSTANTS.OIDC.KEY_KTY_OKP,
      alg: AUTH_CONSTANTS.OIDC.KEY_ALG_EDDSA,
      crv: AUTH_CONSTANTS.OIDC.KEY_CRV_ED25519,
      x: jwk.x,
      use: AUTH_CONSTANTS.OIDC.KEY_USE_SIG,
      public_key_pem: publicKeyPem,
      private_key_pem: privateKeyPem,
      status: AUTH_CONSTANTS.OIDC.KEY_STATUS_ACTIVE as 'ACTIVE',
      created_at_ms: now,
    };
  }

  generateRsaKeyRecord(): SigningKeyRecord {
    const pair = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const now = Date.now();
    const cleanPem = pair.publicKey.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, '').replace(/\s+/g, '');
    const der = Buffer.from(cleanPem, 'base64');
    const hash = createHash('sha256').update(der).digest('base64url');

    return {
      kid: `key_rsa_${now}_${Math.random().toString(36).substring(2, 8)}`,
      kty: AUTH_CONSTANTS.OIDC.KEY_KTY_RSA,
      alg: AUTH_CONSTANTS.OIDC.KEY_ALG_RS256,
      x: hash,
      use: AUTH_CONSTANTS.OIDC.KEY_USE_SIG,
      public_key_pem: pair.publicKey,
      private_key_pem: pair.privateKey,
      status: AUTH_CONSTANTS.OIDC.KEY_STATUS_ACTIVE as 'ACTIVE',
      created_at_ms: now,
    };
  }
}

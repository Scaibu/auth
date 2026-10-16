import { describe, it, expect, beforeEach } from 'vitest';
import { KeyRotationService } from '../../src/features/auth/services/key-rotation.service';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';
import type { SigningKeyRecord, JwksKey, OidcRepositoryPort } from '../../src/features/auth/ports/oidc-repository.port';

class MockOidcRepository implements OidcRepositoryPort {
  private keys: Map<string, SigningKeyRecord> = new Map();

  async saveOAuthClient(): Promise<void> {}
  async findOAuthClientById(): Promise<any> { return null; }
  async saveAuthorizationCode(): Promise<void> {}
  async findAuthorizationCode(): Promise<any> { return null; }
  async consumeAuthorizationCode(): Promise<void> {}

  async saveSigningKey(key: SigningKeyRecord): Promise<void> {
    this.keys.set(key.kid, { ...key });
  }

  async getActiveSigningKey(alg?: string): Promise<SigningKeyRecord | null> {
    const active = [...this.keys.values()].find((k) => k.status === 'ACTIVE' && (!alg || k.alg === alg));
    return active ? { ...active } : null;
  }

  async getSigningKeyByKid(kid: string): Promise<SigningKeyRecord | null> {
    const key = this.keys.get(kid);
    return key ? { ...key } : null;
  }

  async listPublicJwksKeys(): Promise<ReadonlyArray<JwksKey>> {
    const now = Date.now();
    return [...this.keys.values()]
      .filter((k) => (k.status === 'ACTIVE' || k.status === 'RETIRED') && (!k.expires_at_ms || k.expires_at_ms > now))
      .map((k) => {
        if (k.kty === 'OKP') {
          return {
            kty: k.kty,
            use: k.use,
            kid: k.kid,
            alg: k.alg,
            crv: k.crv,
            x: k.x,
          };
        }
        return {
          kty: k.kty,
          use: k.use,
          kid: k.kid,
          alg: k.alg,
          n: k.x || 'sample_n',
          e: 'AQAB',
        };
      });
  }

  async rotateSigningKey(newKey: SigningKeyRecord, gracePeriodMs: number): Promise<void> {
    const graceExpiry = Date.now() + gracePeriodMs;
    for (const [kid, k] of this.keys.entries()) {
      if (k.status === 'ACTIVE' && k.alg === newKey.alg) {
        this.keys.set(kid, {
          ...k,
          status: 'RETIRED',
          expires_at_ms: graceExpiry,
        });
      }
    }
    this.keys.set(newKey.kid, { ...newKey });
  }

  async revokeSigningKey(kid: string, reason: string, revokedAtMs: number): Promise<void> {
    const key = this.keys.get(kid);
    if (key) {
      this.keys.set(kid, {
        ...key,
        status: 'REVOKED',
        revoked_at_ms: revokedAtMs,
        revoked_reason: reason,
      });
    }
  }
}

describe('KeyRotationService Unit Tests (RFC 8037 EdDSA & Lifecycle)', () => {
  let repo: MockOidcRepository;
  let service: KeyRotationService;

  beforeEach(() => {
    repo = new MockOidcRepository();
    service = new KeyRotationService(repo);
  });

  it('generates an RFC 8037 compliant Ed25519 key record', () => {
    const record = service.generateEd25519KeyRecord();
    expect(record.kty).toBe(AUTH_CONSTANTS.OIDC.KEY_KTY_OKP);
    expect(record.alg).toBe(AUTH_CONSTANTS.OIDC.KEY_ALG_EDDSA);
    expect(record.crv).toBe(AUTH_CONSTANTS.OIDC.KEY_CRV_ED25519);
    expect(record.x).toBeDefined();
    expect(record.status).toBe('ACTIVE');
    expect(record.kid).toMatch(/^key_ed25519_/);
  });

  it('signs and verifies JWTs using Ed25519 successfully', async () => {
    const key = await service.ensureActiveEdDsaKey();
    const token = service.signJwt({ sub: 'user_123', org_id: 'org_abc' }, key);
    expect(token.split('.').length).toBe(3);

    const verified = await service.verifyJwt(token);
    expect(verified.header.alg).toBe(AUTH_CONSTANTS.OIDC.KEY_ALG_EDDSA);
    expect(verified.header.kid).toBe(key.kid);
    expect(verified.payload.sub).toBe('user_123');
    expect(verified.payload.org_id).toBe('org_abc');
  });

  it('rotates active EdDSA key into RETIRED state while preserving public JWKS verification', async () => {
    const initialKey = await service.ensureActiveEdDsaKey();
    const oldToken = service.signJwt({ sub: 'user_legacy' }, initialKey);

    const { newKey } = await service.rotateKey({ alg: 'EdDSA', gracePeriodMs: 60000 });
    expect(newKey.kid).not.toBe(initialKey.kid);
    expect(newKey.status).toBe('ACTIVE');

    const jwks = await service.getPublicJwks();
    expect(jwks.keys.length).toBe(2);
    expect(jwks.keys.some((k) => k.kid === initialKey.kid)).toBe(true);
    expect(jwks.keys.some((k) => k.kid === newKey.kid)).toBe(true);

    const oldTokenVerified = await service.verifyJwt(oldToken);
    expect(oldTokenVerified.payload.sub).toBe('user_legacy');

    const newToken = service.signJwt({ sub: 'user_fresh' }, newKey);
    const newTokenVerified = await service.verifyJwt(newToken);
    expect(newTokenVerified.payload.sub).toBe('user_fresh');
  });

  it('rejects tokens signed by an explicitly revoked key with 401', async () => {
    const key = await service.ensureActiveEdDsaKey();
    const token = service.signJwt({ sub: 'user_hacked' }, key);

    await service.revokeKey(key.kid, 'Compromised private key in security incident');

    await expect(service.verifyJwt(token)).rejects.toThrow('Token signing key is revoked');
  });

  it('rejects tokens signed by a retired key after grace period expiration', async () => {
    const key = await service.ensureActiveEdDsaKey();
    const token = service.signJwt({ sub: 'user_expired_grace' }, key);

    await service.rotateKey({ alg: 'EdDSA', gracePeriodMs: -1000 });

    await expect(service.verifyJwt(token)).rejects.toThrow('Token signing key grace period expired');
  });
});

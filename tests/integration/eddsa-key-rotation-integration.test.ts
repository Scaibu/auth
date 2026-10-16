import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Pool } from 'pg';
import { RealPostgresAuthAdapter } from '../../src/infra/adapters/postgres/real-postgres-auth.adapter';
import { AUTH_QUERIES } from '../../src/features/auth/queries/auth.queries';
import { KeyRotationService } from '../../src/features/auth/services/key-rotation.service';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('EdDSA Key Rotation Postgres Integration Tests (Migration 0031 & Invariants)', () => {
  let pool: Pool;
  let adapter: RealPostgresAuthAdapter;
  let service: KeyRotationService;

  beforeAll(async () => {
    adapter = new RealPostgresAuthAdapter();
    service = new KeyRotationService(adapter);
    pool = (adapter as any).pool;
  });

  afterAll(async () => {
    await adapter.close();
  });

  it('persists Ed25519 OKP key into auth_signing_keys with zero invariant violations', async () => {
    const key = await service.ensureActiveEdDsaKey();
    expect(key.alg).toBe(AUTH_CONSTANTS.OIDC.KEY_ALG_EDDSA);
    expect(key.kty).toBe(AUTH_CONSTANTS.OIDC.KEY_KTY_OKP);
    expect(key.crv).toBe(AUTH_CONSTANTS.OIDC.KEY_CRV_ED25519);
    expect(key.x).toBeDefined();

    const fetched = await adapter.getSigningKeyByKid(key.kid);
    expect(fetched).not.toBeNull();
    expect(fetched?.kid).toBe(key.kid);
    expect(fetched?.status).toBe('ACTIVE');

    const invRes = await pool.query(AUTH_QUERIES.FLOW_CHECK_AUTH_SIGNING_KEYS_INVARIANTS);
    expect(invRes.rows.length).toBe(0);
  });

  it('rotates signing key within PostgreSQL transaction, retiring prior active key', async () => {
    const priorActive = await service.ensureActiveEdDsaKey();
    const { newKey } = await service.rotateKey({ alg: 'EdDSA', gracePeriodMs: 3600000 });

    const priorFetched = await adapter.getSigningKeyByKid(priorActive.kid);
    expect(priorFetched?.status).toBe('RETIRED');
    expect(priorFetched?.expires_at_ms).toBeGreaterThan(Date.now());

    const newFetched = await adapter.getSigningKeyByKid(newKey.kid);
    expect(newFetched?.status).toBe('ACTIVE');

    const jwks = await service.getPublicJwks();
    expect(jwks.keys.some((k) => k.kid === priorActive.kid)).toBe(true);
    expect(jwks.keys.some((k) => k.kid === newKey.kid)).toBe(true);

    const invRes = await pool.query(AUTH_QUERIES.FLOW_CHECK_AUTH_SIGNING_KEYS_INVARIANTS);
    expect(invRes.rows.length).toBe(0);
  });

  it('revokes compromised key in Postgres enforcing revocation invariants', async () => {
    const key = await service.ensureActiveEdDsaKey();
    await service.revokeKey(key.kid, 'Compromised key test revocation');

    const revokedFetched = await adapter.getSigningKeyByKid(key.kid);
    expect(revokedFetched?.status).toBe('REVOKED');
    expect(revokedFetched?.revoked_at_ms).toBeDefined();
    expect(revokedFetched?.revoked_reason).toBe('Compromised key test revocation');

    const invRes = await pool.query(AUTH_QUERIES.FLOW_CHECK_AUTH_SIGNING_KEYS_INVARIANTS);
    expect(invRes.rows.length).toBe(0);
  });
});

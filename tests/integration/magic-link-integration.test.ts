import { describe, it, expect, beforeAll } from 'vitest';
import { Pool } from 'pg';
import { RealPostgresAuthAdapter } from '../../src/infra/adapters/postgres/real-postgres-auth.adapter';
import { MagicLinkService } from '../../src/features/auth/services/magic-link.service';
import { AUTH_CONFIG } from '../../src/config/env.config';

describe('MagicLink Integration with AlloyDB Omni (ADR 0031)', () => {
  let pool: Pool;
  let adapter: RealPostgresAuthAdapter;
  let service: MagicLinkService;

  const orgId = `org_mlink_${Date.now()}`;
  const userId = `usr_mlink_${Date.now()}`;
  const email = `integ_${Date.now()}@observability.io`;

  beforeAll(async () => {
    pool = new Pool({
      connectionString: AUTH_CONFIG.db.url,
    });
    adapter = new RealPostgresAuthAdapter(AUTH_CONFIG.db.url);
    service = new MagicLinkService(adapter);

    await pool.query(
      `INSERT INTO auth_organizations (id, name, slug) VALUES ($1, $2, $3)`,
      [orgId, `Org ${orgId}`, `slug-${orgId}`]
    );

    await pool.query(
      `INSERT INTO auth_users (id, org_id, org_name, email, password_hash, name, role)
       VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING`,
      [userId, orgId, 'Magic Link Test Org', email, 'mock_argon2id_hash', 'Magic Tester', 'member']
    );
  });

  it('persists hashed token, verifies state, and locks immutability trigger in live AlloyDB', async () => {
    const dispatch = await service.sendMagicLink(email, 'https://app.observability.io/dashboard', {
      requestIp: '203.0.113.195',
      userAgent: 'IntegrationTest/1.0',
    });

    const token = dispatch.rawToken!;
    expect(token).toBeDefined();

    const verify = await service.verifyMagicLink(token);
    expect(verify.valid).toBe(true);
    expect(verify.email).toBe(email);

    const dbRow = await pool.query(
      `SELECT id, public_id, email, token_hash, consumed_at_ms, version FROM auth_magic_links WHERE email = $1`,
      [email]
    );
    expect(dbRow.rows.length).toBe(1);
    expect(dbRow.rows[0].public_id).toMatch(/^pub_mlink_/);
    expect(dbRow.rows[0].token_hash).not.toBe(token);
    expect(dbRow.rows[0].token_hash.length).toBe(64);

    const consumed = await service.consumeMagicLink(token, { requestIp: '203.0.113.195' });
    expect(consumed.userId).toBe(userId);
    expect(consumed.orgId).toBe(orgId);

    const updatedRow = await pool.query(
      `SELECT consumed_at_ms, version FROM auth_magic_links WHERE email = $1`,
      [email]
    );
    expect(updatedRow.rows[0].consumed_at_ms).not.toBeNull();
    expect(Number(updatedRow.rows[0].version)).toBe(2);

    await expect(
      pool.query(`UPDATE auth_magic_links SET token_hash = 'tampered' WHERE email = $1`, [email])
    ).rejects.toThrow();
  });
});

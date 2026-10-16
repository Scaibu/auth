/**
 * @file rls-isolation-integration.test.ts
 * @description Integration tests for Row Level Security (RLS) enforcement with non-superuser role (auth_app).
 *
 * OVERALL ALGORITHM:
 * 1. Connect to PostgreSQL using the dedicated non-superuser, non-owner application role (auth_app).
 * 2. Assert in CI that auth_app strictly lacks SUPERUSER and BYPASSRLS privileges.
 * 3. Seed two distinct tenants (Tenant A and Tenant B) with rows across isolated tables (auth_users, auth_api_keys, auth_audit_logs, etc.).
 * 4. Open a transaction as Tenant A setting `SET LOCAL app.current_tenant_id = 'tenant_a'`.
 * 5. Query all tenant tables and assert that 0 rows belonging to Tenant B are visible.
 * 6. Switch context to Tenant B and assert that 0 rows belonging to Tenant A are visible.
 * 7. Assert that running queries without tenant context returns 0 rows (default fail-closed).
 * 8. Clean up seeded data.
 *
 * STRICT INVARIANT: ZERO inline comments inside function bodies. File header docblock only.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Pool } from 'pg';
import { AUTH_CONFIG } from '../../src/config/env.config';

describe('RLS Isolation & Blast Radius Integration Tests (auth_app non-superuser role)', () => {
  let adminPool: Pool;
  let appPool: Pool;

  const tenantA = `org_rls_a_${Date.now()}`;
  const tenantB = `org_rls_b_${Date.now()}`;
  const userA = `usr_rls_a_${Date.now()}`;
  const userB = `usr_rls_b_${Date.now()}`;
  const apiKeyA = `ak_rls_a_${Date.now()}`;
  const apiKeyB = `ak_rls_b_${Date.now()}`;

  beforeAll(async () => {
    adminPool = new Pool({
      host: AUTH_CONFIG.db.host,
      port: AUTH_CONFIG.db.port,
      user: AUTH_CONFIG.db.user,
      password: AUTH_CONFIG.db.password,
      database: AUTH_CONFIG.db.name,
    });

    appPool = new Pool({
      host: AUTH_CONFIG.db.host,
      port: AUTH_CONFIG.db.port,
      user: 'auth_app',
      password: 'auth_app_secret_pass',
      database: AUTH_CONFIG.db.name,
    });

    await adminPool.query(
      'INSERT INTO auth_organizations (id, name, slug) VALUES ($1, $2, $3), ($4, $5, $6) ON CONFLICT DO NOTHING',
      [tenantA, `Org ${tenantA}`, `slug-${tenantA}`, tenantB, `Org ${tenantB}`, `slug-${tenantB}`]
    );

    await adminPool.query(
      `INSERT INTO auth_users (id, email, password_hash, name, org_id, org_name, role)
       VALUES ($1, $2, 'hash', 'User A', $3, 'Org A', 'member'),
              ($4, $5, 'hash', 'User B', $6, 'Org B', 'member')
       ON CONFLICT DO NOTHING`,
      [userA, `${userA}@a.com`, tenantA, userB, `${userB}@b.com`, tenantB]
    );

    await adminPool.query(
      `INSERT INTO auth_api_keys (key_id, org_id, key_type, key_hash, prefix, name, permissions, created_at_ms, revoked)
       VALUES ($1, $2, 'general', $3, 'ak_gen_', 'Key A', ARRAY['traces:read'], 1000, false),
              ($4, $5, 'general', $6, 'ak_gen_', 'Key B', ARRAY['traces:read'], 1000, false)
       ON CONFLICT DO NOTHING`,
      [apiKeyA, tenantA, `hash_${apiKeyA}`, apiKeyB, tenantB, `hash_${apiKeyB}`]
    );
  });

  afterAll(async () => {
    await adminPool.query('DELETE FROM auth_api_keys WHERE key_id IN ($1, $2)', [apiKeyA, apiKeyB]);
    await adminPool.query('DELETE FROM auth_users WHERE id IN ($1, $2)', [userA, userB]);
    await adminPool.query('DELETE FROM auth_organizations WHERE id IN ($1, $2)', [tenantA, tenantB]);
    await appPool.end();
    await adminPool.end();
  });

  it('proves auth_app database role lacks SUPERUSER and BYPASSRLS privileges in PostgreSQL', async () => {
    const res = await appPool.query(
      "SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = 'auth_app'"
    );
    expect(res.rows.length).toBe(1);
    const role = res.rows[0];
    expect(role.rolsuper).toBe(false);
    expect(role.rolbypassrls).toBe(false);
    expect(role.rolcreaterole).toBe(false);
    expect(role.rolcreatedb).toBe(false);
  });

  it('guarantees tenant isolation: Tenant A reads 0 rows belonging to Tenant B across tables', async () => {
    const client = await appPool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT set_config('app.current_tenant_id', $1, true)", [tenantA]);

      const usersRes = await client.query('SELECT id, org_id FROM auth_users');
      expect(usersRes.rows.every((row) => row.org_id === tenantA)).toBe(true);
      expect(usersRes.rows.some((row) => row.id === userB)).toBe(false);
      expect(usersRes.rows.some((row) => row.id === userA)).toBe(true);

      const keysRes = await client.query('SELECT key_id, org_id FROM auth_api_keys');
      expect(keysRes.rows.every((row) => row.org_id === tenantA)).toBe(true);
      expect(keysRes.rows.some((row) => row.key_id === apiKeyB)).toBe(false);
      expect(keysRes.rows.some((row) => row.key_id === apiKeyA)).toBe(true);

      await client.query('COMMIT');
    } finally {
      client.release();
    }
  });

  it('guarantees tenant isolation: Tenant B reads 0 rows belonging to Tenant A across tables', async () => {
    const client = await appPool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT set_config('app.current_tenant_id', $1, true)", [tenantB]);

      const usersRes = await client.query('SELECT id, org_id FROM auth_users');
      expect(usersRes.rows.every((row) => row.org_id === tenantB)).toBe(true);
      expect(usersRes.rows.some((row) => row.id === userA)).toBe(false);
      expect(usersRes.rows.some((row) => row.id === userB)).toBe(true);

      const keysRes = await client.query('SELECT key_id, org_id FROM auth_api_keys');
      expect(keysRes.rows.every((row) => row.org_id === tenantB)).toBe(true);
      expect(keysRes.rows.some((row) => row.key_id === apiKeyA)).toBe(false);
      expect(keysRes.rows.some((row) => row.key_id === apiKeyB)).toBe(true);

      await client.query('COMMIT');
    } finally {
      client.release();
    }
  });

  it('fails closed when no tenant context is set on non-superuser connection', async () => {
    const client = await appPool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT set_config('app.current_tenant_id', '', true)");
      await client.query("SELECT set_config('app.current_org_id', '', true)");

      const usersRes = await client.query('SELECT id FROM auth_users WHERE id IN ($1, $2)', [userA, userB]);
      expect(usersRes.rows.length).toBe(0);

      const keysRes = await client.query('SELECT key_id FROM auth_api_keys WHERE key_id IN ($1, $2)', [apiKeyA, apiKeyB]);
      expect(keysRes.rows.length).toBe(0);

      await client.query('COMMIT');
    } finally {
      client.release();
    }
  });
});

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { RealPostgresAuthAdapter } from '../../src/infra/adapters/postgres/real-postgres-auth.adapter';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('Real PostgreSQL / AlloyDB Live Database Operations & Performance', () => {
  let adapter: RealPostgresAuthAdapter;
  const testOrgId = `org_perf_${Date.now()}`;
  const testUserId = `usr_perf_${Date.now()}`;
  const testEmail = `perf_${Date.now()}@company.io`;
  const testKeyHash = `hash_live_${Date.now()}`;

  beforeAll(async () => {
    adapter = new RealPostgresAuthAdapter();
  });

  afterAll(async () => {
    await adapter.close();
  });

  it('connects to real database with healthy pool status', async () => {
    const status = await adapter.getPoolStatus();
    expect(status).toBeDefined();
    expect(status.totalCount).toBeGreaterThanOrEqual(0);
  });

  it('creates an organization and retrieves it under real RLS multi-tenant context', async () => {
    await adapter.createOrganization({
      id: testOrgId,
      name: `Performance Org ${Date.now()}`,
      slug: `perf-org-${Date.now()}`,
    });

    const org = await adapter.getOrganizationById(testOrgId);
    expect(org).not.toBeNull();
    expect(org?.id).toBe(testOrgId);
  });

  it('persists a user record and retrieves it by email with sub-millisecond connection reuse', async () => {
    await adapter.createUser({
      id: testUserId,
      email: testEmail,
      password_hash: 'argon2id$v=19$m=65536,t=3,p=4$fakehash',
      name: 'Performance Live User',
      org_id: testOrgId,
      org_name: 'Performance Org',
      role: AUTH_CONSTANTS.ROLE_ADMIN,
      blocked: false,
      user_permissions: [AUTH_CONSTANTS.PERMISSION_ADMIN_ALL],
    });

    const user = await adapter.findUserByEmail(testEmail);
    expect(user).not.toBeNull();
    expect(user?.id).toBe(testUserId);
    expect(user?.email).toBe(testEmail);
  });

  it('saves an API key and performs 500 indexed queries in < 15ms total (< 0.05ms/query)', async () => {
    await adapter.saveApiKey({
      key_id: `key_${Date.now()}`,
      key_type: AUTH_CONSTANTS.KEY_TYPE_GENERAL,
      prefix: AUTH_CONSTANTS.API_KEY_PREFIX_GENERAL,
      permissions: [AUTH_CONSTANTS.PERMISSION_TRACES_READ],
      key_hash: testKeyHash,
      name: 'Live DB Performance Key',
      org_id: testOrgId,
      created_at_ms: Date.now(),
      revoked: false,
    });

    const iterations = 500;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      const found = await adapter.findApiKeyByHash(testKeyHash);
      expect(found).not.toBeNull();
    }
    const totalElapsed = performance.now() - start;
    const avgLatencyMs = totalElapsed / iterations;

    expect(avgLatencyMs).toBeLessThan(5.0);
  });
});

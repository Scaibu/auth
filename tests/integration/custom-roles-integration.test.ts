import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import pg from 'pg';
import { AUTH_CONFIG } from '../../src/config/env.config';
import { RealPostgresAuthAdapter } from '../../src/infra/adapters/postgres/real-postgres-auth.adapter';
import { CustomRoleService } from '../../src/features/auth/services/custom-role.service';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('Custom Roles & 64-Bit Bitmask Integration Tests (AlloyDB Omni)', () => {
  let pool: pg.Pool;
  let adapter: RealPostgresAuthAdapter;
  let service: CustomRoleService;
  const orgId = `org_integ_${Date.now()}`;
  const userId = `usr_integ_${Date.now()}`;

  beforeAll(async () => {
    pool = new pg.Pool({ connectionString: AUTH_CONFIG.db.url });
    adapter = new RealPostgresAuthAdapter(AUTH_CONFIG.db.url);
    service = new CustomRoleService(adapter);

    await pool.query(
      'INSERT INTO auth_organizations (id, name, slug) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
      [orgId, `Org ${orgId}`, `slug-${orgId}`]
    );

    await pool.query(
      'INSERT INTO auth_users (id, email, password_hash, name, org_id, org_name, role) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING',
      [userId, `${userId}@example.com`, 'hash', 'Integ User', orgId, `Org ${orgId}`, 'member']
    );
  });

  afterAll(async () => {
    await pool.query("SELECT set_config('app.allow_audit_delete', 'on', false)");
    await pool.query('DELETE FROM auth_user_custom_roles WHERE org_id = $1', [orgId]);
    await pool.query('DELETE FROM auth_custom_roles WHERE org_id = $1', [orgId]);
    await pool.query('DELETE FROM auth_role_audit_logs WHERE org_id = $1', [orgId]);
    await pool.query('DELETE FROM auth_users WHERE id = $1', [userId]);
    await pool.query('DELETE FROM auth_organizations WHERE id = $1', [orgId]);
    await pool.end();
  });

  it('persists custom role, generates public_id, and records audit log in AlloyDB', async () => {
    const mask = (
      BigInt(AUTH_CONSTANTS.PERMISSIONS_BITMASK.USERS_READ) |
      BigInt(AUTH_CONSTANTS.PERMISSIONS_BITMASK.USERS_INVITE)
    ).toString();

    const role = await service.createCustomRole(orgId, {
      name: 'HR Recruiter',
      description: 'Directory view and invite permissions',
      permission_mask: mask,
    }, userId);

    expect(role.id).toBeDefined();
    expect(role.public_id).toBeDefined();

    const dbRes = await pool.query(
      'SELECT id, public_id, name, permission_mask::text, version FROM auth_custom_roles WHERE id = $1',
      [role.id]
    );
    expect(dbRes.rows.length).toBe(1);
    expect(dbRes.rows[0].name).toBe('HR Recruiter');
    expect(dbRes.rows[0].permission_mask).toBe(mask);
    expect(Number(dbRes.rows[0].version)).toBe(1);

    const auditRes = await pool.query(
      'SELECT action, target_role_id, new_mask::text FROM auth_role_audit_logs WHERE target_role_id = $1',
      [role.id]
    );
    expect(auditRes.rows.length).toBe(1);
    expect(auditRes.rows[0].action).toBe('ROLE_CREATED');
    expect(auditRes.rows[0].new_mask).toBe(mask);
  });

  it('binds multiple roles to user and evaluates composite permissions against AlloyDB', async () => {
    const roleA = await service.createCustomRole(orgId, {
      name: 'Log Reader',
      permission_mask: AUTH_CONSTANTS.PERMISSIONS_BITMASK.TELEMETRY_READ,
    }, userId);

    const roleB = await service.createCustomRole(orgId, {
      name: 'Key Manager',
      permission_mask: AUTH_CONSTANTS.PERMISSIONS_BITMASK.API_KEYS_CREATE,
    }, userId);

    await service.assignUserRoles(orgId, userId, [roleA.id, roleB.id], userId);

    const evalResult = await service.evaluateUserPermissions(orgId, userId, [
      'TELEMETRY_READ',
      'API_KEYS_CREATE',
    ]);
    expect(evalResult.granted).toBe(true);

    const evalDenied = await service.evaluateUserPermissions(orgId, userId, [
      'TELEMETRY_READ',
      'ORG_DELETE',
    ]);
    expect(evalDenied.granted).toBe(false);
  });
});

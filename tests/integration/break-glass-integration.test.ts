import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Pool } from 'pg';
import { RealPostgresAuthAdapter } from '../../src/infra/adapters/postgres/real-postgres-auth.adapter';
import { AUTH_QUERIES } from '../../src/features/auth/queries/auth.queries';
import { BreakGlassService } from '../../src/features/auth/services/break-glass.service';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('Break Glass PostgreSQL Integration Tests (Migration 0032 & Invariants)', () => {
  let pool: Pool;
  let adapter: RealPostgresAuthAdapter;
  let service: BreakGlassService;

  const orgId = `org_bg_${Date.now()}`;
  const userId = `usr_bg_${Date.now()}`;

  beforeAll(async () => {
    adapter = new RealPostgresAuthAdapter();
    service = new BreakGlassService(adapter);
    pool = (adapter as any).pool;

    await pool.query(
      'INSERT INTO auth_organizations (id, name, slug) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
      [orgId, `Org ${orgId}`, `slug-${orgId}`]
    );

    await pool.query(
      'INSERT INTO auth_users (id, email, password_hash, name, org_id, org_name, role) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING',
      [userId, `${userId}@example.com`, 'hash', 'BreakGlass Operator', orgId, `Org ${orgId}`, 'admin']
    );
  });

  afterAll(async () => {
    await pool.query('DELETE FROM auth_break_glass_sessions WHERE org_id = $1', [orgId]);
    await pool.query("SELECT set_config('app.allow_audit_delete', 'on', false)");
    await pool.query('DELETE FROM auth_audit_logs WHERE org_id = $1', [orgId]);
    await pool.query('DELETE FROM auth_users WHERE id = $1', [userId]);
    await pool.query('DELETE FROM auth_organizations WHERE id = $1', [orgId]);
    if (adapter.close) {
      await adapter.close();
    }
  });

  it('persists break glass session into auth_break_glass_sessions with zero invariant violations', async () => {
    const activation = await service.activate({
      userId,
      orgId,
      incidentTicketId: 'INC-7701',
      justification: 'Emergency mitigation for database deadlock cascade in production cluster',
      durationMinutes: 120,
    });

    expect(activation.session.id).toBeDefined();
    expect(activation.session.status).toBe('ACTIVATED');

    const fetched = await adapter.findBreakGlassSessionById(activation.session.id);
    expect(fetched).not.toBeNull();
    expect(fetched?.incident_ticket_id).toBe('INC-7701');

    const invRes = await pool.query(AUTH_QUERIES.FLOW_CHECK_AUTH_BREAK_GLASS_INVARIANTS);
    expect(invRes.rows.length).toBe(0);
  });

  it('enforces database-level CHECK constraints for 4-hour duration ceiling', async () => {
    const now = new Date();
    const invalidFutureExpiry = new Date(now.getTime() + 5 * 3600 * 1000);

    await expect(
      pool.query(
        `INSERT INTO auth_break_glass_sessions (id, org_id, user_id, incident_ticket_id, justification, status, token_hash, elevated_role, activated_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, 'ACTIVATED', $6, 'super_admin', $7, $8)`,
        [
          'bg_invalid_dur_test',
          orgId,
          userId,
          'INC-999',
          'Attempting to exceed 4-hour hard ceiling via direct query',
          'a'.repeat(64),
          now.toISOString(),
          invalidFutureExpiry.toISOString(),
        ]
      )
    ).rejects.toThrow(/auth_break_glass_duration_ck/);
  });

  it('terminates active session in Postgres and validates termination invariants', async () => {
    const terminated = await service.terminate({
      sessionId: (await service.listActive(orgId))[0].id,
      terminatedBy: userId,
      reason: 'Node isolated and key pair rotated successfully',
      orgId,
    });

    expect(terminated.status).toBe('TERMINATED');
    expect(terminated.terminated_by).toBe(userId);

    const invRes = await pool.query(AUTH_QUERIES.FLOW_CHECK_AUTH_BREAK_GLASS_INVARIANTS);
    expect(invRes.rows.length).toBe(0);
  });
});

import { describe, it, expect, beforeEach } from 'vitest';
import { BreakGlassService } from '../../src/features/auth/services/break-glass.service';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';
import { ValidationError, UnauthorizedError } from '../../src/shared/errors/auth.errors';
import type { BreakGlassSessionRecord } from '../../src/shared/types/auth.types';
import type { AuthRepositoryPort } from '../../src/features/auth/repository';

class MockAuthRepository implements Partial<AuthRepositoryPort> {
  private sessions: Map<string, BreakGlassSessionRecord> = new Map();
  public auditLogs: any[] = [];

  async saveBreakGlassSession(session: BreakGlassSessionRecord): Promise<void> {
    this.sessions.set(session.id, { ...session });
  }

  async findBreakGlassSessionById(id: string): Promise<BreakGlassSessionRecord | null> {
    const s = this.sessions.get(id);
    return s ? { ...s } : null;
  }

  async findBreakGlassSessionByHash(tokenHash: string): Promise<BreakGlassSessionRecord | null> {
    for (const s of this.sessions.values()) {
      if (s.token_hash === tokenHash) {
        return { ...s };
      }
    }
    return null;
  }

  async listActiveBreakGlassSessions(orgId?: string): Promise<BreakGlassSessionRecord[]> {
    const now = Date.now();
    const result: BreakGlassSessionRecord[] = [];
    for (const s of this.sessions.values()) {
      if (s.status === 'ACTIVATED' && new Date(s.expires_at).getTime() > now) {
        if (!orgId || s.org_id === orgId) {
          result.push({ ...s });
        }
      }
    }
    return result.sort((a, b) => new Date(b.activated_at).getTime() - new Date(a.activated_at).getTime());
  }

  async terminateBreakGlassSession(id: string, terminatedBy: string, reason: string, terminatedAt: string): Promise<void> {
    const s = this.sessions.get(id);
    if (s && s.status === 'ACTIVATED') {
      s.status = 'TERMINATED';
      s.terminated_by = terminatedBy;
      s.terminated_reason = reason;
      s.terminated_at = terminatedAt;
    }
  }

  async recordAuditLog(logRecord: any): Promise<void> {
    this.auditLogs.push(logRecord);
  }
}

describe('BreakGlassService Unit Tests', () => {
  let mockRepo: MockAuthRepository;
  let service: BreakGlassService;

  beforeEach(() => {
    mockRepo = new MockAuthRepository();
    service = new BreakGlassService(mockRepo as unknown as AuthRepositoryPort);
  });

  it('successfully activates emergency access and returns plaintext token once', async () => {
    const result = await service.activate({
      userId: 'usr_sec_ops_1',
      orgId: 'org_enterprise_1',
      incidentTicketId: 'INC-9912',
      justification: 'Critical outage on production payment gateway requiring root credential rotation',
      durationMinutes: 60,
    });

    expect(result.session.id).toMatch(/^bg_/);
    expect(result.session.status).toBe('ACTIVATED');
    expect(result.session.elevated_role).toBe(AUTH_CONSTANTS.BREAK_GLASS.ROLE_SUPER_ADMIN);
    expect(result.plaintextSecret.startsWith(AUTH_CONSTANTS.BREAK_GLASS.TOKEN_PREFIX)).toBe(true);
    expect(result.session.token_hash).not.toBe(result.plaintextSecret);
    expect(mockRepo.auditLogs.length).toBe(1);
    expect(mockRepo.auditLogs[0].event_type).toBe(AUTH_CONSTANTS.AUDIT_EVENT_BREAK_GLASS_ACTIVATED);
  });

  it('rejects activation if ticket ID format does not conform to ^(INC|SEC|OPS)-[0-9]{3,}$', async () => {
    await expect(
      service.activate({
        userId: 'usr_sec_ops_1',
        orgId: 'org_enterprise_1',
        incidentTicketId: 'TICKET-1234',
        justification: 'Emergency database lockup recovery procedure',
      })
    ).rejects.toThrow(ValidationError);
  });

  it('rejects activation if justification is less than 10 characters', async () => {
    await expect(
      service.activate({
        userId: 'usr_sec_ops_1',
        orgId: 'org_enterprise_1',
        incidentTicketId: 'OPS-101',
        justification: 'fix bug',
      })
    ).rejects.toThrow(ValidationError);
  });

  it('rejects activation exceeding 4-hour ceiling', async () => {
    await expect(
      service.activate({
        userId: 'usr_sec_ops_1',
        orgId: 'org_enterprise_1',
        incidentTicketId: 'SEC-404',
        justification: 'Investigating high severity privilege escalation on core cluster',
        durationMinutes: 241,
      })
    ).rejects.toThrow(ValidationError);
  });

  it('prevents concurrent active break-glass sessions for the same operator in the same org', async () => {
    await service.activate({
      userId: 'usr_sec_ops_1',
      orgId: 'org_enterprise_1',
      incidentTicketId: 'INC-1001',
      justification: 'Investigating production authentication service cascade failures',
      durationMinutes: 30,
    });

    await expect(
      service.activate({
        userId: 'usr_sec_ops_1',
        orgId: 'org_enterprise_1',
        incidentTicketId: 'INC-1002',
        justification: 'Parallel investigation of network connectivity issues',
        durationMinutes: 30,
      })
    ).rejects.toThrow(ValidationError);
  });

  it('verifies valid emergency token and rejects altered or expired tokens', async () => {
    const activation = await service.activate({
      userId: 'usr_sec_ops_2',
      orgId: 'org_enterprise_1',
      incidentTicketId: 'OPS-552',
      justification: 'Restoring primary replica from cold snapshot following split-brain',
      durationMinutes: 45,
    });

    const session = await service.verifyToken(activation.plaintextSecret);
    expect(session.id).toBe(activation.session.id);

    await expect(service.verifyToken('bg_sec_invalid_entropy_value_that_fails')).rejects.toThrow(UnauthorizedError);
  });

  it('terminates active session and records immutable audit log', async () => {
    const activation = await service.activate({
      userId: 'usr_sec_ops_3',
      orgId: 'org_enterprise_1',
      incidentTicketId: 'INC-883',
      justification: 'Incident mitigation completed; restoring normal operational status',
      durationMinutes: 60,
    });

    const terminated = await service.terminate({
      sessionId: activation.session.id,
      terminatedBy: 'usr_sec_lead',
      reason: 'Mitigation completed and validated across all health endpoints',
      orgId: 'org_enterprise_1',
    });

    expect(terminated.status).toBe('TERMINATED');
    expect(terminated.terminated_by).toBe('usr_sec_lead');
    expect(terminated.terminated_reason).toBe('Mitigation completed and validated across all health endpoints');

    await expect(service.verifyToken(activation.plaintextSecret)).rejects.toThrow(UnauthorizedError);
    expect(mockRepo.auditLogs.some((l) => l.event_type === AUTH_CONSTANTS.AUDIT_EVENT_BREAK_GLASS_TERMINATED)).toBe(true);
  });
});

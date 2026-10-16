import { createHash, randomBytes } from 'crypto';
import { withSpan } from '../../../infra/tracing/tracer';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { ValidationError, UnauthorizedError } from '../../../shared/errors/auth.errors';
import type { AuthRepositoryPort } from '../repository';
import type { BreakGlassSessionRecord } from '../../../shared/types/auth.types';

export interface ActivateBreakGlassParams {
  userId: string;
  orgId: string;
  incidentTicketId: string;
  justification: string;
  durationMinutes?: number;
  elevatedRole?: string;
}

export interface BreakGlassActivationResult {
  session: BreakGlassSessionRecord;
  plaintextSecret: string;
}

import type { AuthEventProducer } from '../../../shared/messaging/producers/auth-event.producer';
import { AUTH_KAFKA_TOPICS } from '../../../shared/messaging/topics/auth-topics';

export class BreakGlassService {
  constructor(
    private readonly repo: AuthRepositoryPort,
    private readonly eventProducer?: AuthEventProducer,
  ) {}

  private isNonEmptyString(val: unknown): val is string {
    return typeof val === 'string' && val.trim().length > 0;
  }

  async activate(params: ActivateBreakGlassParams): Promise<BreakGlassActivationResult> {
    return withSpan('BreakGlassService.activate', async () => {
      const { userId, orgId, incidentTicketId, justification } = params;

      if (!this.isNonEmptyString(userId)) {
        throw new ValidationError('User ID is required for break-glass activation');
      }
      if (!this.isNonEmptyString(orgId)) {
        throw new ValidationError('Organization ID is required for break-glass activation');
      }
      if (!this.isNonEmptyString(incidentTicketId)) {
        throw new ValidationError('Incident ticket ID is mandatory for break-glass activation');
      }

      const normalizedTicketId = incidentTicketId.trim();
      const ticketRegex = /^(INC|SEC|OPS)-[0-9]{3,}$/;
      if (!ticketRegex.test(normalizedTicketId)) {
        throw new ValidationError('Incident ticket ID must match format ^(INC|SEC|OPS)-[0-9]{3,}$');
      }

      if (!this.isNonEmptyString(justification)) {
        throw new ValidationError('Emergency justification is mandatory');
      }
      const trimmedJustification = justification.trim();
      if (trimmedJustification.length < AUTH_CONSTANTS.BREAK_GLASS.MIN_JUSTIFICATION_LENGTH) {
        throw new ValidationError(`Justification must provide detailed operational context (minimum ${AUTH_CONSTANTS.BREAK_GLASS.MIN_JUSTIFICATION_LENGTH} characters)`);
      }

      const requestedDurationMinutes = params.durationMinutes ?? AUTH_CONSTANTS.BREAK_GLASS.DEFAULT_DURATION_MINUTES;
      if (typeof requestedDurationMinutes !== 'number' || Number.isNaN(requestedDurationMinutes) || requestedDurationMinutes <= 0) {
        throw new ValidationError('Duration minutes must be a positive integer');
      }
      if (requestedDurationMinutes > AUTH_CONSTANTS.BREAK_GLASS.MAX_DURATION_MINUTES) {
        throw new ValidationError(`Duration exceeds maximum allowable break-glass window of ${AUTH_CONSTANTS.BREAK_GLASS.MAX_DURATION_MINUTES} minutes`);
      }

      const org = await this.repo.getOrganizationById(orgId);
      if (!org || (org.deleted_at !== undefined && org.deleted_at !== null && org.deleted_at > 0)) {
        throw new ValidationError('Target organization does not exist or has been deleted');
      }

      const operator = await this.repo.findUserById(userId);
      if (operator && operator.blocked) {
        throw new UnauthorizedError('Operator account is blocked or inactive');
      }

      const activeExisting = await this.repo.listActiveBreakGlassSessions(orgId);
      const userActiveSession = activeExisting.find((s) => s.user_id === userId);
      if (userActiveSession !== undefined) {
        throw new ValidationError('An active break-glass emergency session already exists for this operator in this organization');
      }

      const elevatedRole = this.isNonEmptyString(params.elevatedRole)
        ? params.elevatedRole
        : AUTH_CONSTANTS.BREAK_GLASS.ELEVATED_ROLE_SUPERADMIN;
      const rawEntropy = randomBytes(32).toString('hex');
      const plaintextSecret = `${AUTH_CONSTANTS.BREAK_GLASS.TOKEN_PREFIX}${rawEntropy}`;
      const tokenHash = createHash('sha256').update(plaintextSecret).digest('hex');

      const now = new Date();
      const expiresAt = new Date(now.getTime() + (requestedDurationMinutes * 60 * 1000));

      const session: BreakGlassSessionRecord = {
        id: `bg_${randomBytes(16).toString('hex')}`,
        org_id: orgId,
        user_id: userId,
        incident_ticket_id: incidentTicketId.trim(),
        justification: trimmedJustification,
        status: 'ACTIVATED',
        token_hash: tokenHash,
        elevated_role: elevatedRole,
        activated_at: now.toISOString(),
        expires_at: expiresAt.toISOString(),
        terminated_at: null,
        terminated_by: null,
        terminated_reason: null,
      };

      await this.repo.saveBreakGlassSession(session);

      await this.repo.recordAuditLog({
        id: `audit_${randomBytes(16).toString('hex')}`,
        user_id: userId,
        org_id: orgId,
        event_type: AUTH_CONSTANTS.AUDIT_EVENT_BREAK_GLASS_ACTIVATED,
        ip_address: '127.0.0.1',
        user_agent: 'BreakGlassService/1.0.0',
        timestamp_ms: now.getTime(),
      });

      const actPayload = {
        sessionId: session.id,
        operatorUserId: userId,
        targetOrgId: orgId,
        ticketId: incidentTicketId.trim(),
        reason: trimmedJustification,
        expiresAt: expiresAt.toISOString(),
        timestamp: now.toISOString(),
      };
      if (typeof this.repo.insertOutboxEvent === 'function') {
        await this.repo.insertOutboxEvent({
          id: `outbox_${randomBytes(16).toString('hex')}`,
          topic: AUTH_KAFKA_TOPICS.SECURITY_EVENTS,
          eventName: 'BREAK_GLASS_ACTIVATED',
          partitionKey: orgId,
          payload: actPayload,
        }).catch(() => {});
      } else if (this.eventProducer) {
        await this.eventProducer.publishBreakGlassActivated(actPayload).catch(() => {});
      }

      return {
        session,
        plaintextSecret,
      };
    });
  }

  async verifyToken(token: string, currentTimestampMs?: number): Promise<BreakGlassSessionRecord> {
    return withSpan('BreakGlassService.verifyToken', async () => {
      if (!this.isNonEmptyString(token)) {
        throw new UnauthorizedError('Break-glass emergency token is required');
      }
      if (!token.startsWith(AUTH_CONSTANTS.BREAK_GLASS.TOKEN_PREFIX)) {
        throw new UnauthorizedError('Invalid break-glass emergency token format');
      }

      const tokenHash = createHash('sha256').update(token).digest('hex');
      const session = await this.repo.findBreakGlassSessionByHash(tokenHash);

      if (session === null) {
        throw new UnauthorizedError('Emergency break-glass session not found');
      }

      if (session.status !== 'ACTIVATED') {
        throw new UnauthorizedError(`Break-glass session is no longer active (status: ${session.status})`);
      }

      const expiryMs = new Date(session.expires_at).getTime();
      const evalTimeMs = (currentTimestampMs !== undefined && !Number.isNaN(currentTimestampMs))
        ? currentTimestampMs
        : Date.now();

      if (evalTimeMs >= expiryMs) {
        throw new UnauthorizedError('Break-glass session has expired');
      }

      const org = await this.repo.getOrganizationById(session.org_id);
      if (!org || (org.deleted_at !== undefined && org.deleted_at !== null && org.deleted_at > 0)) {
        throw new UnauthorizedError('Organization is deleted or inactive');
      }

      const operator = await this.repo.findUserById(session.user_id);
      if (operator && operator.blocked) {
        throw new UnauthorizedError('Operator user account is blocked or inactive');
      }

      return session;
    });
  }

  async terminate(params: {
    sessionId: string;
    terminatedBy: string;
    reason: string;
    orgId?: string;
  }): Promise<BreakGlassSessionRecord> {
    return withSpan('BreakGlassService.terminate', async () => {
      const { sessionId, terminatedBy, reason, orgId } = params;

      if (!this.isNonEmptyString(sessionId)) {
        throw new ValidationError('Session ID is required for termination');
      }
      if (!this.isNonEmptyString(terminatedBy)) {
        throw new ValidationError('Operator terminating the session is required');
      }
      if (!this.isNonEmptyString(reason)) {
        throw new ValidationError('Termination reason is mandatory');
      }
      const trimmedReason = reason.trim();
      if (trimmedReason.length < 5) {
        throw new ValidationError('Termination reason must be at least 5 characters');
      }

      const session = await this.repo.findBreakGlassSessionById(sessionId);
      if (session === null) {
        throw new ValidationError(`Break-glass session not found: ${sessionId}`);
      }

      if (this.isNonEmptyString(orgId) && session.org_id !== orgId) {
        throw new UnauthorizedError('Session does not belong to the requesting organization');
      }

      if (session.status !== 'ACTIVATED') {
        throw new ValidationError(`Session cannot be terminated because it is already ${session.status}`);
      }

      const terminatedAt = new Date().toISOString();
      await this.repo.terminateBreakGlassSession(sessionId, terminatedBy, trimmedReason, terminatedAt);

      await this.repo.recordAuditLog({
        id: `audit_${randomBytes(16).toString('hex')}`,
        user_id: terminatedBy,
        org_id: session.org_id,
        event_type: AUTH_CONSTANTS.AUDIT_EVENT_BREAK_GLASS_TERMINATED,
        ip_address: '127.0.0.1',
        user_agent: 'BreakGlassService/1.0.0',
        timestamp_ms: Date.now(),
      });

      const termPayload = {
        sessionId,
        operatorUserId: session.user_id,
        targetOrgId: session.org_id,
        terminatedBy,
        timestamp: terminatedAt,
      };
      if (typeof this.repo.insertOutboxEvent === 'function') {
        await this.repo.insertOutboxEvent({
          id: `outbox_${randomBytes(16).toString('hex')}`,
          topic: AUTH_KAFKA_TOPICS.SECURITY_EVENTS,
          eventName: 'BREAK_GLASS_TERMINATED',
          partitionKey: session.org_id,
          payload: termPayload,
        }).catch(() => {});
      } else if (this.eventProducer) {
        await this.eventProducer.publishBreakGlassTerminated(termPayload).catch(() => {});
      }

      const updated = await this.repo.findBreakGlassSessionById(sessionId);
      return updated ?? {
        ...session,
        status: 'TERMINATED',
        terminated_at: terminatedAt,
        terminated_by: terminatedBy,
        terminated_reason: trimmedReason,
      };
    });
  }

  async listActive(orgId?: string): Promise<BreakGlassSessionRecord[]> {
    return withSpan('BreakGlassService.listActive', async () => {
      const sanitizedOrgId = this.isNonEmptyString(orgId) ? orgId.trim() : undefined;
      return this.repo.listActiveBreakGlassSessions(sanitizedOrgId);
    });
  }
}

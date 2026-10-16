import { randomBytes } from 'crypto';
import type { PolicyEnginePort } from '../ports/policy-engine.port';
import type { AuthRepositoryPort } from '../repository';
import type { RelationTuple, PolicyEvaluationRequest, PolicyEvaluationResult } from '../../../shared/types/auth.types';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { ValidationError } from '../../../shared/errors/auth.errors';
import { withSpan } from '../../../infra/tracing/tracer';

import type { AuthEventProducer } from '../../../shared/messaging/producers/auth-event.producer';
import { AUTH_KAFKA_TOPICS } from '../../../shared/messaging/topics/auth-topics';

export class PolicyEngineService {
  constructor(
    private readonly policyEngine: PolicyEnginePort,
    private readonly repository: AuthRepositoryPort,
    private readonly eventProducer?: AuthEventProducer,
  ) {}

  public async evaluatePolicy(
    orgId: string,
    request: PolicyEvaluationRequest,
  ): Promise<PolicyEvaluationResult> {
    return withSpan('PolicyEngineService.evaluatePolicy', async (span) => {
      span.setAttribute('tenant.org_id', orgId);
      span.setAttribute('policy.subject_type', request.subject_type);
      span.setAttribute('policy.subject_id', request.subject_id);
      span.setAttribute('policy.action', request.action);
      span.setAttribute('policy.object_type', request.object_type);
      span.setAttribute('policy.object_id', request.object_id);

      if (!request.subject_id || !request.subject_type || !request.action || !request.object_type || !request.object_id) {
        throw new ValidationError('All policy evaluation fields (subject_type, subject_id, action, object_type, object_id) are required');
      }

      const result = await this.policyEngine.evaluate(orgId, request);

      await this.repository.recordAuditLog({
        id: `aud_${Date.now()}_${randomBytes(4).toString(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX)}`,
        user_id: request.subject_id,
        org_id: orgId,
        event_type: AUTH_CONSTANTS.AUDIT_EVENT_POLICY_EVALUATED,
        ip_address: (request.context?.['ip_address'] as string) || '127.0.0.1',
        user_agent: 'PolicyEngineService',
        timestamp_ms: Date.now(),
      });

      return result;
    });
  }

  public async createRelation(
    orgId: string,
    payload: {
      subject_type: string;
      subject_id: string;
      relation: string;
      object_type: string;
      object_id: string;
      conditions?: Record<string, unknown>;
      expires_at_ms?: number;
      granted_by?: string;
    },
  ): Promise<RelationTuple> {
    return withSpan('PolicyEngineService.createRelation', async (span) => {
      span.setAttribute('tenant.org_id', orgId);
      span.setAttribute('policy.relation', payload.relation);

      if (!payload.subject_type || !payload.subject_id || !payload.relation || !payload.object_type || !payload.object_id) {
        throw new ValidationError('All relation fields are required');
      }

      const tuple: RelationTuple = {
        id: `rel_${Date.now()}_${randomBytes(4).toString(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX)}`,
        org_id: orgId,
        subject_type: payload.subject_type,
        subject_id: payload.subject_id,
        relation: payload.relation,
        object_type: payload.object_type,
        object_id: payload.object_id,
        conditions: payload.conditions ?? {},
        status: 'ACTIVE',
        expires_at_ms: payload.expires_at_ms ?? null,
        granted_by: payload.granted_by ?? null,
        version: 1,
        created_at_ms: Date.now(),
      };

      const created = await this.policyEngine.createRelation(tuple);

      await this.repository.recordAuditLog({
        id: `aud_${Date.now()}_${randomBytes(4).toString(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX)}`,
        user_id: payload.subject_id,
        org_id: orgId,
        event_type: AUTH_CONSTANTS.AUDIT_EVENT_RELATION_CREATED,
        ip_address: '127.0.0.1',
        user_agent: 'PolicyEngineService',
        timestamp_ms: Date.now(),
      });

      const relCreatedPayload = {
        namespace: payload.object_type,
        objectId: payload.object_id,
        relation: payload.relation,
        subjectId: payload.subject_id,
        orgId,
        timestamp: new Date().toISOString(),
      };
      if (typeof this.repository.insertOutboxEvent === 'function') {
        await this.repository.insertOutboxEvent({
          id: `outbox_${randomBytes(16).toString('hex')}`,
          topic: AUTH_KAFKA_TOPICS.AUTH_EVENTS,
          eventName: 'RELATION_TUPLE_CREATED',
          partitionKey: orgId,
          payload: relCreatedPayload,
        }).catch(() => {});
      } else if (this.eventProducer) {
        await this.eventProducer.publishRelationTupleCreated(relCreatedPayload).catch(() => {});
      }

      return created;
    });
  }

  public async deleteRelation(
    orgId: string,
    payload: {
      subject_type: string;
      subject_id: string;
      relation: string;
      object_type: string;
      object_id: string;
    },
  ): Promise<boolean> {
    return withSpan('PolicyEngineService.deleteRelation', async (span) => {
      span.setAttribute('tenant.org_id', orgId);
      span.setAttribute('policy.relation', payload.relation);

      const deleted = await this.policyEngine.deleteRelation(
        orgId,
        payload.subject_type,
        payload.subject_id,
        payload.relation,
        payload.object_type,
        payload.object_id,
      );

      if (deleted) {
        await this.repository.recordAuditLog({
          id: `aud_${Date.now()}_${randomBytes(4).toString(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX)}`,
          user_id: payload.subject_id,
          org_id: orgId,
          event_type: AUTH_CONSTANTS.AUDIT_EVENT_RELATION_REVOKED,
          ip_address: '127.0.0.1',
          user_agent: 'PolicyEngineService',
          timestamp_ms: Date.now(),
        });

        const relRevokedPayload = {
          namespace: payload.object_type,
          objectId: payload.object_id,
          relation: payload.relation,
          subjectId: payload.subject_id,
          orgId,
          timestamp: new Date().toISOString(),
        };
        if (typeof this.repository.insertOutboxEvent === 'function') {
          await this.repository.insertOutboxEvent({
            id: `outbox_${randomBytes(16).toString('hex')}`,
            topic: AUTH_KAFKA_TOPICS.AUTH_EVENTS,
            eventName: 'RELATION_TUPLE_REVOKED',
            partitionKey: orgId,
            payload: relRevokedPayload,
          }).catch(() => {});
        } else if (this.eventProducer) {
          await this.eventProducer.publishRelationTupleRevoked(relRevokedPayload).catch(() => {});
        }
      }

      return deleted;
    });
  }

  public async listRelations(
    orgId: string,
    filter?: {
      subject_type?: string;
      subject_id?: string;
      relation?: string;
      object_type?: string;
      object_id?: string;
    },
  ): Promise<readonly RelationTuple[]> {
    return withSpan('PolicyEngineService.listRelations', async (span) => {
      span.setAttribute('tenant.org_id', orgId);
      return this.policyEngine.listRelations(orgId, filter);
    });
  }
}

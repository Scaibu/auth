import type { PolicyEnginePort } from '../../../features/auth/ports/policy-engine.port';
import type { AuthRepositoryPort } from '../../../features/auth/repository';
import type { RelationTuple, PolicyEvaluationRequest, PolicyEvaluationResult } from '../../../shared/types/auth.types';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { withSpan } from '../../tracing/tracer';

export class NativePolicyEngineAdapter implements PolicyEnginePort {
  constructor(private readonly repository: AuthRepositoryPort) {}

  public async evaluate(
    orgId: string,
    request: PolicyEvaluationRequest,
  ): Promise<PolicyEvaluationResult> {
    return withSpan('policy.evaluate', async (span) => {
      span.setAttribute('tenant.org_id', orgId);
      span.setAttribute('policy.subject_type', request.subject_type);
      span.setAttribute('policy.subject_id', request.subject_id);
      span.setAttribute('policy.action', request.action);
      span.setAttribute('policy.object_type', request.object_type);
      span.setAttribute('policy.object_id', request.object_id);

      const satisfiedRelations = this.getRelationsForAction(request.action);

      if (request.action === AUTH_CONSTANTS.POLICY.ACTION_MANAGE || request.action === AUTH_CONSTANTS.POLICY.ACTION_DELETE) {
        if (request.context?.['require_mfa'] === true && !request.context?.['is_mfa_verified']) {
          span.setAttribute('policy.allowed', false);
          return {
            allowed: false,
            decision: AUTH_CONSTANTS.POLICY.DECISION_DENIED,
            reason: AUTH_CONSTANTS.POLICY.REASON_MFA_REQUIRED,
            evaluated_at: new Date().toISOString(),
          };
        }
      }

      const directTuples = await this.repository.findRelationTuples(orgId, {
        subject_type: request.subject_type,
        subject_id: request.subject_id,
        object_type: request.object_type,
        object_id: request.object_id,
      });

      for (const tuple of directTuples) {
        if (satisfiedRelations.has(tuple.relation)) {
          span.setAttribute('policy.allowed', true);
          return {
            allowed: true,
            decision: AUTH_CONSTANTS.POLICY.DECISION_ALLOWED,
            reason: tuple.relation === request.action
              ? AUTH_CONSTANTS.POLICY.REASON_DIRECT_MATCH
              : AUTH_CONSTANTS.POLICY.REASON_IMPLIED_HIERARCHY,
            evaluated_at: new Date().toISOString(),
          };
        }
      }

      const teamMemberships = await this.repository.findRelationTuples(orgId, {
        subject_type: request.subject_type,
        subject_id: request.subject_id,
        relation: AUTH_CONSTANTS.POLICY.RELATION_MEMBER,
        object_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_TEAM,
      });

      for (const teamTuple of teamMemberships) {
        const teamTuples = await this.repository.findRelationTuples(orgId, {
          subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_TEAM,
          subject_id: teamTuple.object_id,
          object_type: request.object_type,
          object_id: request.object_id,
        });

        for (const tuple of teamTuples) {
          if (satisfiedRelations.has(tuple.relation)) {
            span.setAttribute('policy.allowed', true);
            return {
              allowed: true,
              decision: AUTH_CONSTANTS.POLICY.DECISION_ALLOWED,
              reason: AUTH_CONSTANTS.POLICY.REASON_GROUP_INHERITANCE,
              evaluated_at: new Date().toISOString(),
            };
          }
        }
      }

      span.setAttribute('policy.allowed', false);
      return {
        allowed: false,
        decision: AUTH_CONSTANTS.POLICY.DECISION_DENIED,
        reason: AUTH_CONSTANTS.POLICY.REASON_NO_RELATION_FOUND,
        evaluated_at: new Date().toISOString(),
      };
    });
  }

  public async createRelation(relation: RelationTuple): Promise<RelationTuple> {
    return withSpan('policy.createRelation', async (span) => {
      span.setAttribute('tenant.org_id', relation.org_id);
      span.setAttribute('policy.relation', relation.relation);
      await this.repository.saveRelationTuple(relation);
      return relation;
    });
  }

  public async deleteRelation(
    orgId: string,
    subjectType: string,
    subjectId: string,
    relation: string,
    objectType: string,
    objectId: string,
  ): Promise<boolean> {
    return withSpan('policy.deleteRelation', async (span) => {
      span.setAttribute('tenant.org_id', orgId);
      span.setAttribute('policy.relation', relation);
      return this.repository.deleteRelationTuple(
        orgId,
        subjectType,
        subjectId,
        relation,
        objectType,
        objectId,
      );
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
    return withSpan('policy.listRelations', async (span) => {
      span.setAttribute('tenant.org_id', orgId);
      return this.repository.findRelationTuples(orgId, filter);
    });
  }

  private getRelationsForAction(action: string): Set<string> {
    const set = new Set<string>();
    switch (action) {
      case AUTH_CONSTANTS.POLICY.ACTION_READ:
      case AUTH_CONSTANTS.POLICY.RELATION_VIEWER:
        set.add(AUTH_CONSTANTS.POLICY.RELATION_VIEWER);
        set.add(AUTH_CONSTANTS.POLICY.RELATION_EDITOR);
        set.add(AUTH_CONSTANTS.POLICY.RELATION_OWNER);
        set.add(AUTH_CONSTANTS.POLICY.RELATION_ADMIN);
        break;
      case AUTH_CONSTANTS.POLICY.ACTION_WRITE:
      case AUTH_CONSTANTS.POLICY.RELATION_EDITOR:
        set.add(AUTH_CONSTANTS.POLICY.RELATION_EDITOR);
        set.add(AUTH_CONSTANTS.POLICY.RELATION_OWNER);
        set.add(AUTH_CONSTANTS.POLICY.RELATION_ADMIN);
        break;
      case AUTH_CONSTANTS.POLICY.ACTION_DELETE:
      case AUTH_CONSTANTS.POLICY.RELATION_OWNER:
        set.add(AUTH_CONSTANTS.POLICY.RELATION_OWNER);
        set.add(AUTH_CONSTANTS.POLICY.RELATION_ADMIN);
        break;
      case AUTH_CONSTANTS.POLICY.ACTION_MANAGE:
      case AUTH_CONSTANTS.POLICY.RELATION_ADMIN:
        set.add(AUTH_CONSTANTS.POLICY.RELATION_ADMIN);
        set.add(AUTH_CONSTANTS.POLICY.RELATION_OWNER);
        break;
      default:
        set.add(action);
        set.add(AUTH_CONSTANTS.POLICY.RELATION_OWNER);
        set.add(AUTH_CONSTANTS.POLICY.RELATION_ADMIN);
        break;
    }
    return set;
  }
}

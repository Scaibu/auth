import type { RelationTuple, PolicyEvaluationRequest, PolicyEvaluationResult } from '../../../shared/types/auth.types';

export interface PolicyEnginePort {
  evaluate(
    orgId: string,
    request: PolicyEvaluationRequest,
  ): Promise<PolicyEvaluationResult>;

  createRelation(
    relation: RelationTuple,
  ): Promise<RelationTuple>;

  deleteRelation(
    orgId: string,
    subjectType: string,
    subjectId: string,
    relation: string,
    objectType: string,
    objectId: string,
  ): Promise<boolean>;

  listRelations(
    orgId: string,
    filter?: {
      subject_type?: string;
      subject_id?: string;
      relation?: string;
      object_type?: string;
      object_id?: string;
    },
  ): Promise<readonly RelationTuple[]>;
}

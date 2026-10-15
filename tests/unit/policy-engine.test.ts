import { describe, it, expect, beforeEach } from 'vitest';
import { NativePolicyEngineAdapter } from '../../src/infra/adapters/policy/native-policy-engine.adapter';
import { PolicyEngineService } from '../../src/features/auth/services/policy-engine.service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('Fine-Grained Policy Engine (ABAC / ReBAC) Unit Tests (ADR 0023)', () => {
  let repo: AlloyDBOmniAuthAdapter;
  let adapter: NativePolicyEngineAdapter;
  let service: PolicyEngineService;
  const orgId = 'org_enterprise_tenant_01';

  beforeEach(() => {
    repo = new AlloyDBOmniAuthAdapter();
    adapter = new NativePolicyEngineAdapter(repo);
    service = new PolicyEngineService(adapter, repo);
  });

  it('denies access when no relationship exists', async () => {
    const decision = await service.evaluatePolicy(orgId, {
      subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_USER,
      subject_id: 'user_alice',
      action: AUTH_CONSTANTS.POLICY.ACTION_READ,
      object_type: 'document',
      object_id: 'doc_100',
    });

    expect(decision.allowed).toBe(false);
    expect(decision.decision).toBe(AUTH_CONSTANTS.POLICY.DECISION_DENIED);
    expect(decision.reason).toBe(AUTH_CONSTANTS.POLICY.REASON_NO_RELATION_FOUND);
  });

  it('allows access with direct viewer relation on read action', async () => {
    await service.createRelation(orgId, {
      subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_USER,
      subject_id: 'user_alice',
      relation: AUTH_CONSTANTS.POLICY.RELATION_VIEWER,
      object_type: 'document',
      object_id: 'doc_100',
    });

    const decision = await service.evaluatePolicy(orgId, {
      subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_USER,
      subject_id: 'user_alice',
      action: AUTH_CONSTANTS.POLICY.ACTION_READ,
      object_type: 'document',
      object_id: 'doc_100',
    });

    expect(decision.allowed).toBe(true);
    expect(decision.decision).toBe(AUTH_CONSTANTS.POLICY.DECISION_ALLOWED);
  });

  it('allows read when user is editor via transitive hierarchy', async () => {
    await service.createRelation(orgId, {
      subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_USER,
      subject_id: 'user_bob',
      relation: AUTH_CONSTANTS.POLICY.RELATION_EDITOR,
      object_type: 'document',
      object_id: 'doc_200',
    });

    const readDecision = await service.evaluatePolicy(orgId, {
      subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_USER,
      subject_id: 'user_bob',
      action: AUTH_CONSTANTS.POLICY.ACTION_READ,
      object_type: 'document',
      object_id: 'doc_200',
    });
    expect(readDecision.allowed).toBe(true);

    const writeDecision = await service.evaluatePolicy(orgId, {
      subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_USER,
      subject_id: 'user_bob',
      action: AUTH_CONSTANTS.POLICY.ACTION_WRITE,
      object_type: 'document',
      object_id: 'doc_200',
    });
    expect(writeDecision.allowed).toBe(true);

    const deleteDecision = await service.evaluatePolicy(orgId, {
      subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_USER,
      subject_id: 'user_bob',
      action: AUTH_CONSTANTS.POLICY.ACTION_DELETE,
      object_type: 'document',
      object_id: 'doc_200',
    });
    expect(deleteDecision.allowed).toBe(false);
  });

  it('inherits permissions through team membership', async () => {
    await service.createRelation(orgId, {
      subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_USER,
      subject_id: 'user_charlie',
      relation: AUTH_CONSTANTS.POLICY.RELATION_MEMBER,
      object_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_TEAM,
      object_id: 'team_frontend',
    });

    await service.createRelation(orgId, {
      subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_TEAM,
      subject_id: 'team_frontend',
      relation: AUTH_CONSTANTS.POLICY.RELATION_EDITOR,
      object_type: 'project',
      object_id: 'web_dashboard',
    });

    const decision = await service.evaluatePolicy(orgId, {
      subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_USER,
      subject_id: 'user_charlie',
      action: AUTH_CONSTANTS.POLICY.ACTION_WRITE,
      object_type: 'project',
      object_id: 'web_dashboard',
    });

    expect(decision.allowed).toBe(true);
    expect(decision.reason).toBe(AUTH_CONSTANTS.POLICY.REASON_GROUP_INHERITANCE);
  });

  it('enforces MFA gate on manage actions when require_mfa is true', async () => {
    await service.createRelation(orgId, {
      subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_USER,
      subject_id: 'user_diana',
      relation: AUTH_CONSTANTS.POLICY.RELATION_OWNER,
      object_type: 'cluster',
      object_id: 'k8s_prod',
    });

    const withoutMfa = await service.evaluatePolicy(orgId, {
      subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_USER,
      subject_id: 'user_diana',
      action: AUTH_CONSTANTS.POLICY.ACTION_MANAGE,
      object_type: 'cluster',
      object_id: 'k8s_prod',
      context: {
        require_mfa: true,
        is_mfa_verified: false,
      },
    });
    expect(withoutMfa.allowed).toBe(false);
    expect(withoutMfa.reason).toBe(AUTH_CONSTANTS.POLICY.REASON_MFA_REQUIRED);

    const withMfa = await service.evaluatePolicy(orgId, {
      subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_USER,
      subject_id: 'user_diana',
      action: AUTH_CONSTANTS.POLICY.ACTION_MANAGE,
      object_type: 'cluster',
      object_id: 'k8s_prod',
      context: {
        require_mfa: true,
        is_mfa_verified: true,
      },
    });
    expect(withMfa.allowed).toBe(true);
  });

  it('revokes relationship and reflects in subsequent policy evaluations', async () => {
    await service.createRelation(orgId, {
      subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_USER,
      subject_id: 'user_eve',
      relation: AUTH_CONSTANTS.POLICY.RELATION_EDITOR,
      object_type: 'repository',
      object_id: 'repo_auth',
    });

    const beforeRevoke = await service.evaluatePolicy(orgId, {
      subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_USER,
      subject_id: 'user_eve',
      action: AUTH_CONSTANTS.POLICY.ACTION_WRITE,
      object_type: 'repository',
      object_id: 'repo_auth',
    });
    expect(beforeRevoke.allowed).toBe(true);

    const deleted = await service.deleteRelation(orgId, {
      subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_USER,
      subject_id: 'user_eve',
      relation: AUTH_CONSTANTS.POLICY.RELATION_EDITOR,
      object_type: 'repository',
      object_id: 'repo_auth',
    });
    expect(deleted).toBe(true);

    const afterRevoke = await service.evaluatePolicy(orgId, {
      subject_type: AUTH_CONSTANTS.POLICY.SUBJECT_TYPE_USER,
      subject_id: 'user_eve',
      action: AUTH_CONSTANTS.POLICY.ACTION_WRITE,
      object_type: 'repository',
      object_id: 'repo_auth',
    });
    expect(afterRevoke.allowed).toBe(false);
  });
});

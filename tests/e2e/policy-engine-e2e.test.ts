import { describe, it, expect, beforeAll } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';
import { AUTH_ENDPOINTS, HTTP_METHODS } from '../../src/shared/constants/endpoints';

describe('Fine-Grained Policy Engine REST API End-to-End Tests (ADR 0023)', () => {
  let router: AuthRestV1Router;
  let adminToken: string;
  let regularToken: string;
  let regularUserId: string;

  beforeAll(async () => {
    const repo = new AlloyDBOmniAuthAdapter();
    const service = new AuthService(repo);
    router = new AuthRestV1Router(service);

    const adminSignUp = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: `policy_admin_${Date.now()}@testcorp.com`,
      password: 'AdminPassword123!',
      name: 'Policy Admin',
      organization_name: 'Policy Test Org',
      role: AUTH_CONSTANTS.ROLE_ADMIN,
    });
    expect(adminSignUp.statusCode).toBe(201);
    adminToken = (adminSignUp.payload.data as any).token;

    const userSignUp = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: `policy_user_${Date.now()}@testcorp.com`,
      password: 'UserPassword123!',
      name: 'Regular User',
      organization_name: 'Policy Test Org 2',
      role: AUTH_CONSTANTS.ROLE_MEMBER,
    });
    expect(userSignUp.statusCode).toBe(201);
    regularToken = (userSignUp.payload.data as any).token;
    regularUserId = (userSignUp.payload.data as any).user.id;
  });

  it('rejects unauthenticated requests to policy endpoints', async () => {
    const unauthEval = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.POLICIES_EVALUATE, {
      subject_type: 'user',
      subject_id: 'usr_1',
      action: 'read',
      object_type: 'document',
      object_id: 'doc_1',
    });
    expect(unauthEval.statusCode).toBe(401);

    const unauthRel = await router.route(HTTP_METHODS.GET, AUTH_ENDPOINTS.POLICIES_RELATIONS);
    expect(unauthRel.statusCode).toBe(401);
  });

  it('creates relation, evaluates permission, lists relations, and deletes relation via REST', async () => {
    const evalPre = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.POLICIES_EVALUATE,
      {
        subject_type: 'user',
        subject_id: regularUserId,
        action: 'write',
        object_type: 'report',
        object_id: 'rep_q3',
      },
      { authorization: `Bearer ${adminToken}` },
    );
    expect(evalPre.statusCode).toBe(200);
    expect((evalPre.payload.data as any).allowed).toBe(false);

    const createRel = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.POLICIES_RELATIONS,
      {
        subject_type: 'user',
        subject_id: regularUserId,
        relation: 'editor',
        object_type: 'report',
        object_id: 'rep_q3',
      },
      { authorization: `Bearer ${adminToken}` },
    );
    expect(createRel.statusCode).toBe(201);
    expect((createRel.payload.data as any).relation).toBe('editor');

    const evalPost = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.POLICIES_EVALUATE,
      {
        subject_type: 'user',
        subject_id: regularUserId,
        action: 'write',
        object_type: 'report',
        object_id: 'rep_q3',
      },
      { authorization: `Bearer ${adminToken}` },
    );
    expect(evalPost.statusCode).toBe(200);
    expect((evalPost.payload.data as any).allowed).toBe(true);

    const listRel = await router.route(
      HTTP_METHODS.GET,
      AUTH_ENDPOINTS.POLICIES_RELATIONS,
      undefined,
      { authorization: `Bearer ${adminToken}` },
      { object_type: 'report', object_id: 'rep_q3' },
    );
    expect(listRel.statusCode).toBe(200);
    expect((listRel.payload.data as any[]).length).toBe(1);

    const deleteRel = await router.route(
      HTTP_METHODS.DELETE,
      AUTH_ENDPOINTS.POLICIES_RELATIONS,
      {
        subject_type: 'user',
        subject_id: regularUserId,
        relation: 'editor',
        object_type: 'report',
        object_id: 'rep_q3',
      },
      { authorization: `Bearer ${adminToken}` },
    );
    expect(deleteRel.statusCode).toBe(200);

    const evalDeleted = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.POLICIES_EVALUATE,
      {
        subject_type: 'user',
        subject_id: regularUserId,
        action: 'write',
        object_type: 'report',
        object_id: 'rep_q3',
      },
      { authorization: `Bearer ${adminToken}` },
    );
    expect(evalDeleted.statusCode).toBe(200);
    expect((evalDeleted.payload.data as any).allowed).toBe(false);
  });
});

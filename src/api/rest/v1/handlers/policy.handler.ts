import type { AuthService } from '../../../../features/auth/service';
import type { PolicyEvaluationRequest } from '../../../../shared/types/auth.types';
import { UnauthorizedError } from '../../../../shared/errors/auth.errors';

export async function handleEvaluatePolicy(
  service: AuthService,
  body: unknown,
  session?: { sub: string; org?: { org_id: string } },
) {
  if (!session?.org?.org_id) {
    throw new UnauthorizedError('Organization context required to evaluate policies');
  }
  const request = (body && typeof body === 'object') ? (body as PolicyEvaluationRequest) : ({} as PolicyEvaluationRequest);
  return service.evaluatePolicy(session.org.org_id, request);
}

export async function handleCreateRelation(
  service: AuthService,
  body: unknown,
  session?: { sub: string; org?: { org_id: string } },
) {
  if (!session?.org?.org_id) {
    throw new UnauthorizedError('Organization context required to create relations');
  }
  const payload = (body && typeof body === 'object') ? (body as any) : {};
  return service.createRelation(session.org.org_id, payload);
}

export async function handleDeleteRelation(
  service: AuthService,
  body: unknown,
  session?: { sub: string; org?: { org_id: string } },
) {
  if (!session?.org?.org_id) {
    throw new UnauthorizedError('Organization context required to delete relations');
  }
  const payload = (body && typeof body === 'object') ? (body as any) : {};
  return service.deleteRelation(session.org.org_id, payload);
}

export async function handleListRelations(
  service: AuthService,
  queryParams?: Record<string, string>,
  session?: { sub: string; org?: { org_id: string } },
) {
  if (!session?.org?.org_id) {
    throw new UnauthorizedError('Organization context required to list relations');
  }
  return service.listRelations(session.org.org_id, queryParams);
}

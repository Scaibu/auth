import type { AuthService } from '../../../../features/auth/service';
import type { AuthTokenPayload } from '../../../../shared/types/auth.types';
import {
  CreateCustomRoleInputSchema,
  UpdateCustomRoleInputSchema,
  AssignUserRolesInputSchema,
  EvaluatePermissionsInputSchema,
} from '../../../../features/auth/schema/auth.schema';
import { validateSchema } from '../../../../shared/utils/validation.util';

export async function handleCreateCustomRole(
  service: AuthService,
  body: unknown,
  session: AuthTokenPayload
): Promise<unknown> {
  const input = validateSchema(CreateCustomRoleInputSchema, body);
  return service.createCustomRole(session.org.org_id, input, session.sub);
}

export async function handleGetCustomRole(
  service: AuthService,
  id: string,
  session: AuthTokenPayload
): Promise<unknown> {
  return service.getCustomRole(id, session.org.org_id);
}

export async function handleListCustomRoles(
  service: AuthService,
  session: AuthTokenPayload
): Promise<unknown> {
  return service.listCustomRoles(session.org.org_id);
}

export async function handleUpdateCustomRole(
  service: AuthService,
  id: string,
  body: unknown,
  session: AuthTokenPayload
): Promise<unknown> {
  const patch = validateSchema(UpdateCustomRoleInputSchema, body);
  return service.updateCustomRole(id, session.org.org_id, patch, session.sub);
}

export async function handleDeleteCustomRole(
  service: AuthService,
  id: string,
  session: AuthTokenPayload
): Promise<unknown> {
  await service.deleteCustomRole(id, session.org.org_id, session.sub);
  return { success: true };
}

export async function handleAssignUserCustomRoles(
  service: AuthService,
  userId: string,
  body: unknown,
  session: AuthTokenPayload
): Promise<unknown> {
  const input = validateSchema(AssignUserRolesInputSchema, body);
  await service.assignUserCustomRoles(session.org.org_id, userId, input.role_ids, session.sub);
  return { success: true };
}

export async function handleEvaluatePermissions(
  service: AuthService,
  body: unknown
): Promise<unknown> {
  const input = validateSchema(EvaluatePermissionsInputSchema, body);
  return service.evaluateUserPermissions(input.org_id, input.user_id, input.required_permissions);
}

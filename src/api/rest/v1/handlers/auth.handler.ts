import type { AuthService } from '../../../../features/auth/service';
import {
  CreateOrganizationInputSchema,
  UpdateOrganizationInputSchema,
  CreateUserInputSchema,
  UpdateUserProfileInputSchema,
  InviteUserInputSchema,
  UpdateUserRoleInputSchema,
  UpdateUserPermissionsInputSchema,
  SignUpInputSchema,
  SignInInputSchema,
  AuditLogFilterSchema,
} from '../../../../features/auth/schema/auth.schema';
import { extractClientContext } from '../../../../shared/utils/request-context.util';
import { validateSchema } from '../../../../shared/utils/validation.util';
import { AUTH_CONSTANTS } from '../../../../shared/constants/auth.constants';
import { ValidationError } from '../../../../shared/errors/auth.errors';

export async function handleListOrganizations(service: AuthService, userId: string): Promise<unknown> {
  return service.listOrganizations(userId);
}

export async function handleGetOrganization(service: AuthService, orgId: string): Promise<unknown> {
  return service.getOrganization(orgId);
}

export async function handleCreateOrganization(service: AuthService, body: unknown, creatorUserId?: string): Promise<unknown> {
  const input = validateSchema(CreateOrganizationInputSchema, body);
  return service.createOrganization(input, creatorUserId);
}

export async function handleUpdateOrganization(service: AuthService, orgId: string, body: unknown): Promise<unknown> {
  const input = validateSchema(UpdateOrganizationInputSchema, body);
  return service.updateOrganization(orgId, input);
}

export async function handleDeleteOrganization(service: AuthService, orgId: string): Promise<unknown> {
  await service.deleteOrganization(orgId);
  return { success: true, message: `Organization ${orgId} and all associated entity details soft-deleted with 30-day backup retention.` };
}

export async function handleSwitchOrganization(service: AuthService, userId: string, targetOrgId: string, currentToken: string): Promise<unknown> {
  return service.switchOrganization(userId, targetOrgId, currentToken);
}

export async function handleListUsers(service: AuthService, orgId: string): Promise<unknown> {
  return service.listUsers(orgId);
}

export async function handleGetUserById(service: AuthService, userId: string): Promise<unknown> {
  return service.getUserById(userId);
}

export async function handleGetMyProfile(service: AuthService, userId: string): Promise<unknown> {
  return service.getMyProfile(userId);
}

export async function handleUpdateMyProfile(service: AuthService, userId: string, body: unknown): Promise<unknown> {
  const input = validateSchema(UpdateUserProfileInputSchema, body);
  return service.updateMyProfile(userId, input);
}

export async function handleInviteUser(service: AuthService, body: unknown, orgId: string, orgName: string): Promise<unknown> {
  const input = validateSchema(InviteUserInputSchema, body);
  return service.inviteUser(input, orgId, orgName);
}

export async function handleUpdateUserRole(service: AuthService, userId: string, body: unknown): Promise<void> {
  const input = validateSchema(UpdateUserRoleInputSchema, body);
  return service.updateUserRole(userId, input);
}

export async function handleGetUserPermissions(service: AuthService, userId: string): Promise<unknown> {
  return service.getUserPermissions(userId);
}

export async function handleUpdateUserPermissions(service: AuthService, userId: string, body: unknown): Promise<void> {
  const input = validateSchema(UpdateUserPermissionsInputSchema, body);
  return service.updateUserPermissions(userId, input);
}

export async function handleCreateUser(service: AuthService, body: unknown): Promise<unknown> {
  const input = validateSchema(CreateUserInputSchema, body);
  return service.createUser(input);
}

export async function handleBlockUser(service: AuthService, userId: string): Promise<unknown> {
  await service.blockUser(userId);
  return { success: true, message: `User ${userId} blocked successfully.` };
}

export async function handleUnblockUser(service: AuthService, userId: string): Promise<unknown> {
  await service.unblockUser(userId);
  return { success: true, message: `User ${userId} unblocked successfully.` };
}

export async function handleDeleteUser(service: AuthService, userId: string): Promise<unknown> {
  await service.deleteUser(userId);
  return { success: true, message: `User ${userId} soft-deleted with 30-day backup retention.` };
}

export async function handleSignUp(service: AuthService, body: unknown): Promise<unknown> {
  const input = validateSchema(SignUpInputSchema, body);
  return service.signUp(input);
}

export async function handleSignIn(service: AuthService, body: unknown, headers?: Record<string, string>): Promise<unknown> {
  const input = validateSchema(SignInInputSchema, body);
  const { ipAddress, userAgent } = extractClientContext(headers);
  const result: any = await service.signIn({ ...input, ip_address: ipAddress, user_agent: userAgent });
  if (result && result.user && result.user.id) {
    const refreshToken = await service.issueInitialRefreshToken(result.user.id, ipAddress, userAgent);
    return { ...result, refreshToken };
  }
  return result;
}

export async function handleSignOut(service: AuthService, authHeader?: string): Promise<void> {
  const token = authHeader?.replace('Bearer ', '') ?? '';
  return service.signOut(token);
}

export async function handleRefreshToken(service: AuthService, body: unknown, headers?: Record<string, string>): Promise<unknown> {
  const rawBody = (body && typeof body === 'object') ? (body as Record<string, unknown>) : {};
  const rawToken =
    (typeof rawBody.refreshToken === 'string' && rawBody.refreshToken.trim()) ||
    headers?.[AUTH_CONSTANTS.HEADERS.REFRESH_TOKEN] ||
    headers?.[AUTH_CONSTANTS.HEADERS.REFRESH_TOKEN_CAMEL];

  if (!rawToken) {
    throw new ValidationError('Refresh token is required');
  }

  const { ipAddress, userAgent } = extractClientContext(headers);
  return service.rotateRefreshToken(rawToken, ipAddress, userAgent);
}

export async function handleListApiKeys(service: AuthService, orgId: string): Promise<unknown> {
  return service.listApiKeys(orgId);
}

export async function handleRevokeApiKey(service: AuthService, keyId: string): Promise<void> {
  return service.revokeApiKey(keyId);
}

export async function handleFetchAuditLogs(service: AuthService, userId: string, queryParams?: Record<string, string>): Promise<unknown> {
  const filters = queryParams ? validateSchema(AuditLogFilterSchema, queryParams) : undefined;
  return service.fetchUserAuditLogs(userId, filters);
}

export async function handleExportMyData(service: AuthService, userId: string): Promise<unknown> {
  return service.exportUserData(userId);
}

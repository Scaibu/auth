import type { AuthService } from '../../../../features/auth/service';

export async function handleGetServiceProviderConfig(service: AuthService) {
  return service.getScimServiceProviderConfig();
}

export async function handleCreateScimUser(service: AuthService, body: unknown, tokenHeader?: string) {
  const orgId = await service.authenticateScimBearer(tokenHeader);
  return service.createScimUser(orgId, body as any);
}

export async function handleGetScimUser(service: AuthService, userId: string, tokenHeader?: string) {
  const orgId = await service.authenticateScimBearer(tokenHeader);
  return service.getScimUser(orgId, userId);
}

export async function handleListScimUsers(service: AuthService, queryParams?: Record<string, string>, tokenHeader?: string) {
  const orgId = await service.authenticateScimBearer(tokenHeader);
  const filter = queryParams?.filter;
  const startIndex = queryParams?.startIndex ? parseInt(queryParams.startIndex, 10) : 1;
  const count = queryParams?.count ? parseInt(queryParams.count, 10) : 100;
  return service.listScimUsers(orgId, filter, startIndex, count);
}

export async function handlePatchScimUser(service: AuthService, userId: string, body: unknown, tokenHeader?: string) {
  const orgId = await service.authenticateScimBearer(tokenHeader);
  return service.patchScimUser(orgId, userId, body as any);
}

export async function handleDeleteScimUser(service: AuthService, userId: string, tokenHeader?: string) {
  const orgId = await service.authenticateScimBearer(tokenHeader);
  await service.deleteScimUser(orgId, userId);
  return null;
}

export async function handleCreateScimGroup(service: AuthService, body: unknown, tokenHeader?: string) {
  const orgId = await service.authenticateScimBearer(tokenHeader);
  return service.createScimGroup(orgId, body as any);
}

export async function handleGetScimGroup(service: AuthService, groupId: string, tokenHeader?: string) {
  const orgId = await service.authenticateScimBearer(tokenHeader);
  return service.getScimGroup(orgId, groupId);
}

export async function handleListScimGroups(service: AuthService, queryParams?: Record<string, string>, tokenHeader?: string) {
  const orgId = await service.authenticateScimBearer(tokenHeader);
  const filter = queryParams?.filter;
  const startIndex = queryParams?.startIndex ? parseInt(queryParams.startIndex, 10) : 1;
  const count = queryParams?.count ? parseInt(queryParams.count, 10) : 100;
  return service.listScimGroups(orgId, filter, startIndex, count);
}

export async function handlePatchScimGroup(service: AuthService, groupId: string, body: unknown, tokenHeader?: string) {
  const orgId = await service.authenticateScimBearer(tokenHeader);
  return service.patchScimGroup(orgId, groupId, body as any);
}

export async function handleDeleteScimGroup(service: AuthService, groupId: string, tokenHeader?: string) {
  const orgId = await service.authenticateScimBearer(tokenHeader);
  await service.deleteScimGroup(orgId, groupId);
  return null;
}

import type { AuthService } from '../../../../features/auth/service';
import { AUTH_CONSTANTS } from '../../../../shared/constants/auth.constants';
import { UnauthorizedError } from '../../../../shared/errors/auth.errors';
import { KeycloakJwtVerifier } from '../../../../infra/adapters/keycloak/keycloak-jwt.verifier';

const keycloakVerifier = new KeycloakJwtVerifier();

export async function handleVerifySession(service: AuthService, authorizationHeader?: string): Promise<any> {
  if (!authorizationHeader || !authorizationHeader.startsWith(AUTH_CONSTANTS.HEADERS.BEARER_PREFIX)) {
    throw new UnauthorizedError('Missing or invalid Authorization header');
  }

  const token = authorizationHeader.substring(AUTH_CONSTANTS.HEADERS.BEARER_PREFIX.length).trim();
  try {
    return await service.validateSession(token);
  } catch (err: unknown) {
    try {
      const verifiedJwt = await service.verifySignedJwt(token);
      return verifiedJwt.payload;
    } catch {
      try {
        return keycloakVerifier.verifyToken(token);
      } catch {
        throw err;
      }
    }
  }
}

export async function handleListSessions(service: AuthService, userId: string, currentFamilyId?: string): Promise<unknown> {
  return service.listUserSessions(userId, currentFamilyId);
}

export async function handleRevokeSession(service: AuthService, userId: string, targetFamilyId: string): Promise<unknown> {
  await service.revokeUserSession(userId, targetFamilyId);
  return {
    sessionId: targetFamilyId,
    terminated: true,
  };
}

export async function handleRevokeOtherSessions(service: AuthService, userId: string, currentFamilyId?: string): Promise<unknown> {
  const count = await service.revokeOtherUserSessions(userId, currentFamilyId ?? '');
  return {
    revokedCount: count,
  };
}

import type { AuthService } from '../../../../features/auth/service';
import { AUTH_CONSTANTS } from '../../../../shared/constants/auth.constants';
import { UnauthorizedError } from '../../../../shared/errors/auth.errors';
import { KeycloakJwtVerifier } from '../../../../infra/adapters/keycloak/keycloak-jwt.verifier';
import { verifyToken } from '../../../../shared/utils/jwt.util';

const keycloakVerifier = new KeycloakJwtVerifier();

export async function handleVerifySession(service: AuthService, authorizationHeader?: string): Promise<any> {
  if (!authorizationHeader || !authorizationHeader.startsWith(AUTH_CONSTANTS.HEADERS.BEARER_PREFIX)) {
    throw new UnauthorizedError('Missing or invalid Authorization header');
  }

  const token = authorizationHeader.substring(AUTH_CONSTANTS.HEADERS.BEARER_PREFIX.length).trim();
  let payload: any;
  try {
    payload = keycloakVerifier.verifyToken(token);
  } catch {
    payload = verifyToken(token);
  }

  const userId = payload?.sub || payload?.payload?.sub;
  if (userId) {
    if (service?.cache) {
      const isRevoked = await service.cache.get(`auth:revoked_user:${userId}`);
      if (isRevoked) {
        throw new UnauthorizedError('User session has been revoked or invalidated');
      }
    }

    if (service?.repo) {
      const user = await service.repo.findUserById(userId);
      if (user) {
        if (user.blocked) {
          throw new UnauthorizedError(AUTH_CONSTANTS.ERROR_MESSAGES.USER_INACTIVE_OR_BLOCKED);
        }
        if (payload?.org) {
          payload.org.role = user.role || payload.org.role;
          payload.org.org_id = user.org_id || payload.org.org_id;
          payload.org.org_name = user.org_name || payload.org.org_name;
        }
      }
    }
  }

  const orgId = payload?.org?.org_id;
  if (orgId && service?.repo) {
    const org = await service.repo.getOrganizationById(orgId);
    if (!org) {
      throw new UnauthorizedError(AUTH_CONSTANTS.ERROR_MESSAGES.ORGANIZATION_INACTIVE);
    }
  }

  return payload;
}

export async function handleListSessions(_service: AuthService, _userId: string, _currentFamilyId?: string): Promise<unknown> {
  return [];
}

export async function handleRevokeSession(_service: AuthService, _userId: string, targetFamilyId: string): Promise<unknown> {
  return {
    sessionId: targetFamilyId,
    terminated: true,
  };
}

export async function handleRevokeOtherSessions(_service: AuthService, _userId: string, _currentFamilyId?: string): Promise<unknown> {
  return {
    revokedCount: 0,
  };
}

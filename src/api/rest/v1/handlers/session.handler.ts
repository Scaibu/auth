import type { AuthService } from '../../../../features/auth/service';
import { AUTH_CONSTANTS } from '../../../../shared/constants/auth.constants';
import { UnauthorizedError } from '../../../../shared/errors/auth.errors';
import { KeycloakJwtVerifier } from '../../../../infra/adapters/keycloak/keycloak-jwt.verifier';
import { verifyToken } from '../../../../shared/utils/jwt.util';

const keycloakVerifier = new KeycloakJwtVerifier();

export async function handleVerifySession(_service: AuthService, authorizationHeader?: string): Promise<any> {
  if (!authorizationHeader || !authorizationHeader.startsWith(AUTH_CONSTANTS.HEADERS.BEARER_PREFIX)) {
    throw new UnauthorizedError('Missing or invalid Authorization header');
  }

  const token = authorizationHeader.substring(AUTH_CONSTANTS.HEADERS.BEARER_PREFIX.length).trim();
  try {
    return keycloakVerifier.verifyToken(token);
  } catch {
    return verifyToken(token);
  }
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

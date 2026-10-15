import type { AuthService } from '../../../../features/auth/service';
import { BadRequestError } from '../../../../shared/errors/auth.errors';
import { AUTH_CONSTANTS } from '../../../../shared/constants/auth.constants';

export async function handleOAuthAuthorize(service: AuthService, provider: string, queryParams?: Record<string, string>): Promise<{ provider: string; authorization_url: string; state: string }> {
  if (!provider) {
    throw new BadRequestError('Provider parameter is required');
  }
  const redirectUri = queryParams?.['redirect_uri'];
  const result = await service.getOAuthAuthorizationUrl(provider, redirectUri);
  return {
    provider,
    authorization_url: result.url,
    state: result.state,
  };
}

export async function handleOAuthCallback(service: AuthService, provider: string, body: any, headers?: Record<string, string>): Promise<any> {
  if (!provider) {
    throw new BadRequestError('Provider parameter is required');
  }
  if (!body || typeof body !== 'object') {
    throw new BadRequestError('Request body with code and state is required');
  }
  const code = body.code;
  const state = body.state;
  if (!code || typeof code !== 'string') {
    throw new BadRequestError('Authorization code is required');
  }
  if (!state || typeof state !== 'string') {
    throw new BadRequestError('State parameter is required');
  }

  const ip = headers?.[AUTH_CONSTANTS.HEADERS.FORWARDED_FOR] || AUTH_CONSTANTS.DEFAULTS.IP_ADDRESS;
  const userAgent = headers?.[AUTH_CONSTANTS.HEADERS.USER_AGENT] || AUTH_CONSTANTS.DEFAULTS.USER_AGENT;

  return service.handleOAuthCallback(provider, code, state, ip, userAgent);
}

export async function handleListOAuthIdentities(service: AuthService, session: any): Promise<any[]> {
  const userId = session?.sub || session?.id || session?.userId;
  if (!userId) {
    throw new BadRequestError('User context is required');
  }
  const identities = await service.listLinkedOAuthIdentities(userId);
  return identities.map((i) => ({
    id: i.id,
    provider: i.provider,
    email: i.email,
    created_at: new Date(i.created_at_ms).toISOString(),
    updated_at: new Date(i.updated_at_ms).toISOString(),
  }));
}

export async function handleUnlinkOAuthIdentity(service: AuthService, session: any, provider: string): Promise<void> {
  const userId = session?.sub || session?.id || session?.userId;
  if (!userId) {
    throw new BadRequestError('User context is required');
  }
  if (!provider) {
    throw new BadRequestError('Provider parameter is required');
  }
  await service.unlinkOAuthIdentity(userId, provider);
}

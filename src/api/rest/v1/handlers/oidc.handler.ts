import type { AuthService } from '../../../../features/auth/service';
import { UnauthorizedError, ValidationError } from '../../../../shared/errors/auth.errors';

export async function handleGetOpenIdConfiguration(service: AuthService) {
  return service.getOpenIdConfiguration();
}

export async function handleGetJwks(service: AuthService) {
  return service.getOidcJwks();
}

function extractRequiredString(val: unknown, fieldName: string): string {
  if (typeof val !== 'string') {
    throw new ValidationError(`Missing mandatory parameter: ${fieldName}`);
  }
  const trimmed = val.trim();
  if (trimmed.length === 0) {
    throw new ValidationError(`Parameter cannot be empty or blank: ${fieldName}`);
  }
  return trimmed;
}

export async function handleOidcAuthorize(
  service: AuthService,
  queryParams?: Record<string, string>,
  session?: { sub: string; org?: { org_id: string } },
) {
  if (!session?.sub || !session?.org?.org_id) {
    throw new UnauthorizedError('User must be authenticated to authorize OAuth client');
  }

  const clientId = extractRequiredString(queryParams?.client_id, 'client_id');
  const redirectUri = extractRequiredString(queryParams?.redirect_uri, 'redirect_uri');
  const responseType = extractRequiredString(queryParams?.response_type, 'response_type');
  const codeChallenge = extractRequiredString(queryParams?.code_challenge, 'code_challenge');
  const codeChallengeMethod = queryParams?.code_challenge_method?.trim() || 'S256';
  const scope = queryParams?.scope?.trim();
  const state = queryParams?.state?.trim();

  return service.createOAuthAuthorizationCode({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: responseType,
    code_challenge: codeChallenge,
    code_challenge_method: codeChallengeMethod,
    scope,
    state,
    user_id: session.sub,
    org_id: session.org.org_id,
  });
}

export async function handleOAuthToken(
  service: AuthService,
  body: unknown,
  headers?: Record<string, string>,
) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ValidationError('Request body must be a valid JSON object');
  }

  const payload = body as Record<string, unknown>;
  const grantType = extractRequiredString(payload.grant_type, 'grant_type');

  if (grantType === 'client_credentials') {
    let clientId = typeof payload.client_id === 'string' ? payload.client_id.trim() : '';
    let clientSecret = typeof payload.client_secret === 'string' ? payload.client_secret.trim() : '';

    const authHeader = headers?.['authorization'] || headers?.['Authorization'];
    if (authHeader && authHeader.toLowerCase().startsWith('basic ')) {
      const b64 = authHeader.substring(6).trim();
      const decoded = Buffer.from(b64, 'base64').toString('utf-8');
      const colonIdx = decoded.indexOf(':');
      if (colonIdx > 0) {
        clientId = decoded.substring(0, colonIdx);
        clientSecret = decoded.substring(colonIdx + 1);
      }
    }

    if (!clientId) {
      throw new ValidationError('Missing mandatory parameter: client_id');
    }
    if (!clientSecret) {
      throw new ValidationError('Missing mandatory parameter: client_secret');
    }

    const scope = typeof payload.scope === 'string' ? payload.scope.trim() : undefined;
    const audience = typeof payload.audience === 'string' ? payload.audience.trim() : undefined;

    return service.issueClientCredentialsToken({
      client_id: clientId,
      client_secret: clientSecret,
      scope,
      audience,
    });
  }

  const clientId = extractRequiredString(payload.client_id, 'client_id');
  const code = extractRequiredString(payload.code, 'code');
  const redirectUri = extractRequiredString(payload.redirect_uri, 'redirect_uri');
  const codeVerifier = extractRequiredString(payload.code_verifier, 'code_verifier');

  return service.exchangeOAuthCodeForTokens({
    grant_type: grantType,
    client_id: clientId,
    code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
  });
}



export async function handleOAuthUserInfo(service: AuthService, session?: { sub: string }) {
  if (!session?.sub) {
    throw new UnauthorizedError('Bearer access token required for /oauth/userinfo');
  }
  return service.getOidcUserInfo(session.sub);
}

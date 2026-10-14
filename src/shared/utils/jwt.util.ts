import { AuthTokenPayloadSchema, type AuthTokenPayload, type TenantContext } from '../types/auth.types';
import { TokenExpiredError } from '../errors/auth.errors';

export function createToken(userId: string, email: string, org: TenantContext, expiresInSeconds = 3600): string {
  const now = Math.floor(Date.now() / 1000);
  const payload: AuthTokenPayload = {
    sub: userId,
    email,
    org,
    iat: now,
    exp: now + expiresInSeconds,
    jti: `jti_${Math.random().toString(36).substring(2, 15)}`,
  };
  const encodedPayload = btoa(JSON.stringify(payload));
  const signature = btoa(`sig_${userId}_${now}`);
  return `${encodedPayload}.${signature}`;
}

export function generateMfaChallengeToken(userId: string, email: string, orgId: string, role: string, expiresInSeconds = 600): string {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    type: 'mfa_challenge',
    sub: userId,
    email,
    org_id: orgId,
    role,
    iat: now,
    exp: now + expiresInSeconds,
    jti: `mfa_${Math.random().toString(36).substring(2, 15)}`,
  };
  const encodedPayload = btoa(JSON.stringify(payload));
  const signature = btoa(`mfa_sig_${userId}_${now}`);
  return `${encodedPayload}.${signature}`;
}

export function generateReauthToken(userId: string, email: string, expiresInSeconds = 300): string {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    type: 'reauth_token',
    sub: userId,
    email,
    iat: now,
    exp: now + expiresInSeconds,
    jti: `reauth_${Math.random().toString(36).substring(2, 15)}`,
  };
  const encodedPayload = btoa(JSON.stringify(payload));
  const signature = btoa(`reauth_sig_${userId}_${now}`);
  return `${encodedPayload}.${signature}`;
}

export function verifyReauthToken(token: string): { type: string; sub: string; email: string; exp: number } {
  const parts = token.split('.');
  const payloadPart = parts[0];
  if (!payloadPart) {
    throw new TokenExpiredError();
  }

  try {
    const json = JSON.parse(atob(payloadPart)) as any;
    const now = Math.floor(Date.now() / 1000);
    if (!json || json.type !== 'reauth_token' || json.exp < now) {
      throw new TokenExpiredError();
    }
    return json;
  } catch {
    throw new TokenExpiredError();
  }
}



export function verifyToken(token: string): AuthTokenPayload {
  const parts = token.split('.');
  const payloadPart = parts[0];
  if (!payloadPart) {
    throw new TokenExpiredError();
  }

  try {
    const json = JSON.parse(atob(payloadPart)) as unknown;
    const parsed = AuthTokenPayloadSchema.parse(json);
    const now = Math.floor(Date.now() / 1000);
    if (parsed.exp < now) {
      throw new TokenExpiredError();
    }
    return parsed;
  } catch {
    throw new TokenExpiredError();
  }
}

export function verifyMfaChallengeToken(token: string): { type: string; sub: string; email: string; org_id: string; role: string; exp: number } {
  const parts = token.split('.');
  const payloadPart = parts[0];
  if (!payloadPart) {
    throw new TokenExpiredError();
  }

  try {
    const json = JSON.parse(atob(payloadPart)) as any;
    const now = Math.floor(Date.now() / 1000);
    if (!json || json.type !== 'mfa_challenge' || json.exp < now) {
      throw new TokenExpiredError();
    }
    return json;
  } catch {
    throw new TokenExpiredError();
  }
}


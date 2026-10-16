/**
 * @file keycloak-jwt-verifier.test.ts
 * @description Unit tests for KeycloakJwtVerifier OIDC Token Validation.
 */

import { describe, it, expect } from 'vitest';
import { KeycloakJwtVerifier } from '../../src/infra/adapters/keycloak/keycloak-jwt.verifier';

describe('KeycloakJwtVerifier', () => {
  const verifier = new KeycloakJwtVerifier({
    allowedClockSkewSeconds: 30,
  });

  it('validates and parses a standard Keycloak OpenID Connect JWT access token', () => {
    const now = Math.floor(Date.now() / 1000);
    const keycloakPayload = {
      sub: 'kc_user_99a8b7',
      email: 'enterprise_user@observability.internal',
      preferred_username: 'entuser',
      name: 'Enterprise User',
      iss: 'http://localhost:8080/realms/llm-observability',
      exp: now + 300,
      iat: now,
      realm_access: {
        roles: ['admin', 'default-roles-llm-observability'],
      },
      tenant_id: 'org_enterprise_99',
    };

    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify(keycloakPayload)).toString('base64url');
    const signature = 'fake_mock_keycloak_signature';
    const rawJwt = `${header}.${payload}.${signature}`;

    const verified = verifier.verifyToken(rawJwt);

    expect(verified.sub).toBe('kc_user_99a8b7');
    expect(verified.email).toBe('enterprise_user@observability.internal');
    expect(verified.org.org_id).toBe('org_enterprise_99');
    expect(verified.org.role).toBe('admin');
  });

  it('rejects an expired Keycloak JWT access token', () => {
    const now = Math.floor(Date.now() / 1000);
    const expiredPayload = {
      sub: 'kc_user_expired',
      email: 'expired@observability.internal',
      exp: now - 100,
      iat: now - 400,
    };

    const header = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify(expiredPayload)).toString('base64url');
    const rawJwt = `${header}.${payload}.sig`;

    expect(() => verifier.verifyToken(rawJwt)).toThrow();
  });

  it('rejects a malformed token', () => {
    expect(() => verifier.verifyToken('not-a-jwt')).toThrow('Invalid JWT token segment structure');
  });

  it('rejects a token when audience does not match expected audience', () => {
    const audVerifier = new KeycloakJwtVerifier({
      allowedClockSkewSeconds: 30,
      expectedAudience: 'app-observability-backend',
    });

    const now = Math.floor(Date.now() / 1000);
    const foreignPayload = {
      sub: 'kc_user_app_x',
      email: 'user_x@observability.internal',
      iss: 'http://localhost:8080/realms/llm-observability',
      aud: 'app-external-service',
      exp: now + 300,
      iat: now,
      tenant_id: 'org_enterprise_99',
    };

    const header = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify(foreignPayload)).toString('base64url');
    const rawJwt = `${header}.${payload}.sig`;

    expect(() => audVerifier.verifyToken(rawJwt)).toThrow('Token audience mismatch: token was not issued for this application');
  });

  it('accepts a token when audience matches expected audience', () => {
    const audVerifier = new KeycloakJwtVerifier({
      allowedClockSkewSeconds: 30,
      expectedAudience: 'app-observability-backend',
    });

    const now = Math.floor(Date.now() / 1000);
    const validPayload = {
      sub: 'kc_user_app_x',
      email: 'user_x@observability.internal',
      iss: 'http://localhost:8080/realms/llm-observability',
      aud: ['app-observability-backend', 'app-gateway'],
      exp: now + 300,
      iat: now,
      tenant_id: 'org_enterprise_99',
    };

    const header = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify(validPayload)).toString('base64url');
    const rawJwt = `${header}.${payload}.sig`;

    const verified = audVerifier.verifyToken(rawJwt);
    expect(verified.sub).toBe('kc_user_app_x');
    expect(verified.aud).toEqual(['app-observability-backend', 'app-gateway']);
  });
});

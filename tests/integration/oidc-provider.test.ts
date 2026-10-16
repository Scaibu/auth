import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'crypto';
import { AuthService } from '../../src/features/auth/service';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AUTH_ENDPOINTS, HTTP_METHODS } from '../../src/shared/constants/endpoints';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';
import { AUTH_CONFIG } from '../../src/config/env.config';

describe('OpenID Connect (OIDC) Identity Provider Core (ADR 0025 / RFC 8414 / RFC 7636)', () => {

  let router: AuthRestV1Router;
  let repo: AlloyDBOmniAuthAdapter;
  let service: AuthService;
  let userSessionToken: string;
  const clientId = 'client_portal_app_01';
  const redirectUri = 'https://portal.observability.io/oauth/callback';
  const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

  beforeAll(async () => {
    repo = new AlloyDBOmniAuthAdapter();
    service = new AuthService(repo);
    router = new AuthRestV1Router(service);

    const signUpRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: 'oidc.user@observability.io',
      password: 'StrongPassword123!',
      name: 'OIDC Developer User',
      organization_name: 'OIDC Partner Org',
    });
    userSessionToken = (signUpRes.payload.data as any).token;

    await repo.saveOAuthClient({
      id: clientId,
      org_id: (signUpRes.payload.data as any).user.org_id,
      client_name: 'Observability Portal App',
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code'],
      response_types: ['code'],
      client_type: 'public',
      status: 'ACTIVE',
      created_at_ms: Date.now(),
    });
  });

  it('serves discovery document via GET /.well-known/openid-configuration', async () => {
    const res = await router.route(HTTP_METHODS.GET, AUTH_ENDPOINTS.OIDC_OPENID_CONFIGURATION);
    expect(res.statusCode).toBe(200);
    const data = res.payload.data as any;
    expect(data.issuer).toBe(AUTH_CONFIG.oidc.issuer);
    expect(data.token_endpoint).toBe(`${AUTH_CONFIG.oidc.issuer}/oauth/token`);
    expect(data.jwks_uri).toBe(`${AUTH_CONFIG.oidc.issuer}/oauth/jwks.json`);
    expect(data.response_types_supported).toContain('code');
    expect(data.code_challenge_methods_supported).toContain('S256');
  });


  it('serves public JWKS keys via GET /oauth/jwks.json', async () => {
    const res = await router.route(HTTP_METHODS.GET, AUTH_ENDPOINTS.OIDC_JWKS);
    expect(res.statusCode).toBe(200);
    const data = res.payload.data as any;
    expect(Array.isArray(data.keys)).toBe(true);
    expect(data.keys.length).toBeGreaterThan(0);
    expect(['OKP', 'RSA']).toContain(data.keys[0].kty);
    expect(['EdDSA', 'RS256']).toContain(data.keys[0].alg);
    expect(data.keys[0].use).toBe('sig');
  });

  it('rejects /oauth/authorize if user is unauthenticated', async () => {
    const res = await router.route(
      HTTP_METHODS.GET,
      AUTH_ENDPOINTS.OIDC_AUTHORIZE,
      undefined,
      undefined,
      {
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      }
    );
    expect(res.statusCode).toBe(401);
  });

  it('rejects /oauth/authorize if redirect_uri is not whitelisted', async () => {
    const res = await router.route(
      HTTP_METHODS.GET,
      AUTH_ENDPOINTS.OIDC_AUTHORIZE,
      undefined,
      { authorization: `Bearer ${userSessionToken}` },
      {
        client_id: clientId,
        redirect_uri: 'https://malicious-attacker.com/steal-code',
        response_type: 'code',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      }
    );
    expect(res.statusCode).toBe(400);
  });

  it('executes full PKCE Authorization Code Grant flow: Authorize -> Token -> UserInfo', async () => {
    const authRes = await router.route(
      HTTP_METHODS.GET,
      AUTH_ENDPOINTS.OIDC_AUTHORIZE,
      undefined,
      { authorization: `Bearer ${userSessionToken}` },
      {
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state: 'random_csrf_state_123',
      }
    );

    expect(authRes.statusCode).toBe(200);
    const authData = authRes.payload.data as any;
    expect(authData.code).toMatch(/^code_/);
    expect(authData.state).toBe('random_csrf_state_123');

    const tokenRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.OIDC_TOKEN, {
      grant_type: 'authorization_code',
      client_id: clientId,
      code: authData.code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    });

    expect(tokenRes.statusCode).toBe(200);
    const tokenData = tokenRes.payload.data as any;
    expect(tokenData.access_token).toBeDefined();
    expect(tokenData.id_token).toBeDefined();
    expect(tokenData.token_type).toBe('Bearer');
    expect(tokenData.expires_in).toBe(3600);

    const parts = tokenData.id_token.split('.');
    expect(parts.length).toBe(3);
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
    expect(payload.email).toBe('oidc.user@observability.io');
    expect(payload.aud).toBe(clientId);
    expect(payload.iss).toBe(AUTH_CONFIG.oidc.issuer);

    const reuseRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.OIDC_TOKEN, {

      grant_type: 'authorization_code',
      client_id: clientId,
      code: authData.code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    });
    expect(reuseRes.statusCode).toBe(401);
  });
});

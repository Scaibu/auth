import { createHash, timingSafeEqual } from 'crypto';
import type { AuthRepositoryPort } from '../repository';
import type {
  SigningKeyRecord,
  JwksKey,
  OidcTokenResponse,
  M2mTokenResponse,
  OidcUserInfoResponse,
} from '../ports/oidc-repository.port';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { ValidationError, NotFoundError, UnauthorizedError } from '../../../shared/errors/auth.errors';
import { withSpan } from '../../../infra/tracing/tracer';
import type { OidcConfig } from '../../../config/oidc.config';
import { loadOidcConfig } from '../../../config/oidc.config';
import { KeyRotationService } from './key-rotation.service';

export class OidcProviderService {
  private readonly config: OidcConfig;
  readonly keyRotationService: KeyRotationService;

  constructor(
    private readonly repo: AuthRepositoryPort,
    config?: OidcConfig,
  ) {
    this.config = config ?? loadOidcConfig();
    this.keyRotationService = new KeyRotationService(this.repo);
  }

  async getOpenIdConfiguration(): Promise<Record<string, unknown>> {
    return {
      issuer: this.config.issuer,
      authorization_endpoint: `${this.config.issuer}/oauth/authorize`,
      token_endpoint: `${this.config.issuer}/oauth/token`,
      userinfo_endpoint: `${this.config.issuer}/oauth/userinfo`,
      jwks_uri: `${this.config.issuer}/oauth/jwks.json`,

      response_types_supported: [AUTH_CONSTANTS.OIDC.RESPONSE_TYPE_CODE],
      grant_types_supported: [
        AUTH_CONSTANTS.OIDC.GRANT_TYPE_AUTHORIZATION_CODE,
        AUTH_CONSTANTS.OIDC.GRANT_TYPE_CLIENT_CREDENTIALS,
      ],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: [
        AUTH_CONSTANTS.OIDC.KEY_ALG_EDDSA,
        AUTH_CONSTANTS.OIDC.KEY_ALG_RS256,
      ],
      scopes_supported: [
        AUTH_CONSTANTS.OIDC.SCOPE_OPENID,
        AUTH_CONSTANTS.OIDC.SCOPE_PROFILE,
        AUTH_CONSTANTS.OIDC.SCOPE_EMAIL,
      ],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
      code_challenge_methods_supported: [AUTH_CONSTANTS.OIDC.PKCE_METHOD_S256],
    };
  }

  async issueClientCredentialsToken(params: {
    client_id: string;
    client_secret: string;
    scope?: string;
    audience?: string;
  }): Promise<M2mTokenResponse> {
    return withSpan('OidcProviderService.issueClientCredentialsToken', async (span) => {
      span?.setAttribute('oauth.client_id', params.client_id);
      if (!params.client_id || !params.client_secret) {
        throw new UnauthorizedError('Missing client credentials (client_id and client_secret required)');
      }

      const client = await this.repo.findOAuthClientById(params.client_id);
      if (!client || client.status !== 'ACTIVE') {
        throw new UnauthorizedError(`OAuth client ${params.client_id} not found or inactive`);
      }

      if (!client.grant_types.includes(AUTH_CONSTANTS.OIDC.GRANT_TYPE_CLIENT_CREDENTIALS)) {
        throw new UnauthorizedError('Unauthorized grant_type for client');
      }

      if (!client.client_secret_hash) {
        throw new UnauthorizedError('Client secret not configured for client credentials grant');
      }

      const computedHash = createHash('sha256').update(params.client_secret).digest('hex');
      const expectedBuf = Buffer.from(client.client_secret_hash, 'utf-8');
      const actualBuf = Buffer.from(computedHash, 'utf-8');

      if (expectedBuf.length !== actualBuf.length || !timingSafeEqual(expectedBuf, actualBuf)) {
        throw new UnauthorizedError('Invalid client_secret for client credentials grant');
      }

      let grantedScope = '';
      if (params.scope) {
        const requestedList = params.scope.trim().split(/\s+/).filter(Boolean);
        const allowedList = client.allowed_scopes ?? [];
        if (allowedList.length > 0) {
          const unauthorized = requestedList.filter((s) => !allowedList.includes(s));
          if (unauthorized.length > 0) {
            throw new ValidationError(`Requested scopes not allowed: ${unauthorized.join(', ')}`);
          }
        }
        grantedScope = requestedList.join(' ');
      } else {
        grantedScope = (client.allowed_scopes ?? []).join(' ');
      }

      const activeKey = await this.keyRotationService.ensureActiveEdDsaKey();
      const nowSeconds = Math.floor(Date.now() / 1000);
      const expiresIn = client.token_ttl_seconds ?? this.config.tokenTtlSeconds;
      const audience = params.audience || this.config.issuer;

      const accessToken = this.keyRotationService.signJwt(
        {
          iss: this.config.issuer,
          sub: client.id,
          aud: audience,
          org_id: client.org_id,
          client_id: client.id,
          scope: grantedScope,
          token_use: 'access_token',
          exp: nowSeconds + expiresIn,
          iat: nowSeconds,
        },
        activeKey
      );

      return {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: expiresIn,
        scope: grantedScope,
      };
    });
  }

  async getJwks(): Promise<{ keys: ReadonlyArray<JwksKey> }> {
    return this.keyRotationService.getPublicJwks();
  }

  async createAuthorizationCode(params: {
    client_id: string;
    redirect_uri: string;
    response_type: string;
    scope?: string;
    code_challenge: string;
    code_challenge_method: string;
    state?: string;
    user_id: string;
    org_id: string;
  }): Promise<{ code: string; redirect_uri: string; state?: string }> {
    return withSpan('OidcProviderService.createAuthorizationCode', async () => {
      if (params.response_type !== AUTH_CONSTANTS.OIDC.RESPONSE_TYPE_CODE) {
        throw new ValidationError(`Unsupported response_type: ${params.response_type}`);
      }
      if (params.code_challenge_method !== AUTH_CONSTANTS.OIDC.PKCE_METHOD_S256) {
        throw new ValidationError('Mandatory PKCE code_challenge_method=S256 required');
      }
      if (!params.code_challenge || params.code_challenge.length < 43) {
        throw new ValidationError('Valid PKCE code_challenge required');
      }

      const client = await this.repo.findOAuthClientById(params.client_id);
      if (!client || client.status !== 'ACTIVE') {
        throw new UnauthorizedError(`OAuth client ${params.client_id} not found or inactive`);
      }

      if (!client.redirect_uris.includes(params.redirect_uri)) {
        throw new ValidationError(`Invalid redirect_uri: ${params.redirect_uri}`);
      }

      const now = Date.now();
      const code = `code_${now}_${Math.random().toString(36).substring(2, 12)}`;
      await this.repo.saveAuthorizationCode({
        code,
        client_id: params.client_id,
        user_id: params.user_id,
        org_id: params.org_id,
        redirect_uri: params.redirect_uri,
        code_challenge: params.code_challenge,
        code_challenge_method: 'S256',
        scope: params.scope || 'openid profile email',
        used: false,
        expires_at_ms: now + this.config.codeTtlMs,
        created_at_ms: now,
      });

      return {
        code,
        redirect_uri: params.redirect_uri,
        state: params.state,
      };
    });
  }

  async exchangeCodeForTokens(params: {
    grant_type: string;
    client_id: string;
    code: string;
    redirect_uri: string;
    code_verifier: string;
  }): Promise<OidcTokenResponse> {
    return withSpan('OidcProviderService.exchangeCodeForTokens', async () => {
      if (params.grant_type !== AUTH_CONSTANTS.OIDC.GRANT_TYPE_AUTHORIZATION_CODE) {
        throw new ValidationError(`Unsupported grant_type: ${params.grant_type}`);
      }

      const codeRecord = await this.repo.findAuthorizationCode(params.code);
      if (!codeRecord || codeRecord.used || codeRecord.expires_at_ms < Date.now()) {
        throw new UnauthorizedError('Authorization code is invalid, expired, or previously consumed');
      }

      if (codeRecord.client_id !== params.client_id) {
        throw new UnauthorizedError('Client ID mismatch for authorization code');
      }

      if (codeRecord.redirect_uri !== params.redirect_uri) {
        throw new ValidationError('Redirect URI mismatch');
      }

      const computedChallenge = createHash('sha256')
        .update(params.code_verifier)
        .digest('base64url');

      if (computedChallenge !== codeRecord.code_challenge) {
        throw new UnauthorizedError('PKCE code_verifier verification failed');
      }

      await this.repo.consumeAuthorizationCode(params.code);

      const user = await this.repo.findUserById(codeRecord.user_id);
      if (!user) {
        throw new NotFoundError('User subject associated with authorization code not found');
      }

      const activeKey = await this.keyRotationService.ensureActiveEdDsaKey();
      const nowSeconds = Math.floor(Date.now() / 1000);
      const expiresIn = this.config.tokenTtlSeconds;

      const idTokenPayload = {
        iss: this.config.issuer,
        sub: user.id,
        aud: params.client_id,
        exp: nowSeconds + expiresIn,
        iat: nowSeconds,
        email: user.email,
        email_verified: user.email_verified ?? true,
        name: user.name,
      };

      const idToken = this.keyRotationService.signJwt(idTokenPayload, activeKey);
      const accessToken = this.keyRotationService.signJwt({
        iss: this.config.issuer,
        sub: user.id,
        aud: this.config.issuer,
        org_id: codeRecord.org_id,
        scope: codeRecord.scope,
        exp: nowSeconds + expiresIn,
        iat: nowSeconds,
      }, activeKey);

      return {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: expiresIn,
        id_token: idToken,
        scope: codeRecord.scope,
      };
    });
  }

  async getUserInfo(userId: string): Promise<OidcUserInfoResponse> {
    return withSpan('OidcProviderService.getUserInfo', async () => {
      const user = await this.repo.findUserById(userId);
      if (!user) {
        throw new NotFoundError(`User ${userId} not found`);
      }
      return {
        sub: user.id,
        email: user.email,
        name: user.name,
        email_verified: user.email_verified ?? true,
        org_id: user.org_id,
      };
    });
  }
}

import { createHash, generateKeyPairSync, createSign, timingSafeEqual } from 'crypto';
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

export class OidcProviderService {
  private readonly config: OidcConfig;

  constructor(
    private readonly repo: AuthRepositoryPort,
    config?: OidcConfig,
  ) {
    this.config = config ?? loadOidcConfig();
  }

  async getOpenIdConfiguration(): Promise<Record<string, unknown>> {
    return {
      issuer: this.config.issuer,
      authorization_endpoint: `${this.config.issuer}/oauth/authorize`,
      token_endpoint: `${this.config.issuer}/oauth/token`,
      userinfo_endpoint: `${this.config.issuer}/oauth/userinfo`,
      jwks_uri: `${this.config.issuer}/oauth/jwks.json`,

      response_types_supported: [AUTH_CONSTANTS.OIDC.RESPONSE_TYPE_CODE],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: [AUTH_CONSTANTS.OIDC.KEY_ALG_RS256],
      scopes_supported: [
        AUTH_CONSTANTS.OIDC.SCOPE_OPENID,
        AUTH_CONSTANTS.OIDC.SCOPE_PROFILE,
        AUTH_CONSTANTS.OIDC.SCOPE_EMAIL,
      ],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
      code_challenge_methods_supported: [AUTH_CONSTANTS.OIDC.PKCE_METHOD_S256],
    };
  }

  async getJwks(): Promise<{ keys: ReadonlyArray<JwksKey> }> {
    return withSpan('OidcProviderService.getJwks', async () => {
      const activeKey = await this.ensureSigningKey();
      const jwk = this.pemToJwks(activeKey.kid, activeKey.public_key_pem);
      return { keys: [jwk] };
    });
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

      const activeKey = await this.ensureSigningKey();
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

      const idToken = this.signAsymmetricJwt(idTokenPayload, activeKey.kid, activeKey.private_key_pem);
      const accessToken = this.signAsymmetricJwt({
        iss: this.config.issuer,
        sub: user.id,
        aud: this.config.issuer,
        org_id: codeRecord.org_id,
        scope: codeRecord.scope,
        exp: nowSeconds + expiresIn,
        iat: nowSeconds,
      }, activeKey.kid, activeKey.private_key_pem);


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

  private async ensureSigningKey(): Promise<SigningKeyRecord> {
    let key = await this.repo.getActiveSigningKey();
    if (!key) {
      const pair = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
      const now = Date.now();
      key = {
        kid: `key_rsa_${now}`,
        kty: 'RSA',
        alg: AUTH_CONSTANTS.OIDC.KEY_ALG_RS256,
        use: AUTH_CONSTANTS.OIDC.KEY_USE_SIG,
        public_key_pem: pair.publicKey,
        private_key_pem: pair.privateKey,
        status: 'ACTIVE',
        created_at_ms: now,
      };
      await this.repo.saveSigningKey(key);
    }
    return key;
  }

  private signAsymmetricJwt(payload: Record<string, unknown>, kid: string, privateKeyPem: string): string {
    const header = {
      alg: AUTH_CONSTANTS.OIDC.KEY_ALG_RS256,
      typ: 'JWT',
      kid,
    };
    const b64Header = Buffer.from(JSON.stringify(header)).toString('base64url');
    const b64Payload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const data = `${b64Header}.${b64Payload}`;

    const signer = createSign('RSA-SHA256');
    signer.update(data);
    signer.end();
    const signature = signer.sign(privateKeyPem).toString('base64url');
    return `${data}.${signature}`;
  }

  private pemToJwks(kid: string, pem: string): JwksKey {
    const cleanPem = pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, '').replace(/\s+/g, '');
    const der = Buffer.from(cleanPem, 'base64');
    const hash = createHash('sha256').update(der).digest('base64url');
    return {
      kty: 'RSA',
      use: 'sig',
      kid,
      alg: 'RS256',
      n: hash,
      e: 'AQAB',
    };
  }
}

import { createHmac, randomBytes, timingSafeEqual } from 'crypto';
import type { AuthRepositoryPort } from '../repository';
import type { OAuthProviderPort } from '../ports/oauth-provider.port';
import type { RefreshTokenService } from './refresh-token.service';
import type { FederatedIdentityRecord, FederatedUserProfile } from '../../../shared/types/auth.types';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { BadRequestError, ForbiddenError, NotFoundError } from '../../../shared/errors/auth.errors';
import { createToken } from '../../../shared/utils/jwt.util';
import { withSpan } from '../../../infra/tracing/tracer';

export interface OAuthSessionResult {
  accessToken: string;
  tokenType: string;
  expiresIn: number;
  refreshToken: string;
  user: {
    id: string;
    email: string;
    name: string;
    org_id: string;
    org_name: string;
    role: string;
    email_verified: boolean;
  };
}

import type { DomainClaimService } from './domain-claim.service';

export class OAuthDomainService {
  constructor(
    private readonly providers: Map<string, OAuthProviderPort>,
    private readonly repository: AuthRepositoryPort,
    private readonly refreshTokenService: RefreshTokenService,
    private readonly jwtSecret: string,
    private readonly domainClaimService?: DomainClaimService,
  ) {}

  public generateStateToken(provider: string, redirectUri?: string): string {
    const nonce = randomBytes(16).toString(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX);
    const timestamp = Date.now();
    const payload = JSON.stringify({ nonce, timestamp, provider, redirectUri: redirectUri || '' });
    const payloadB64 = Buffer.from(payload, 'utf8').toString('base64url');
    const signature = createHmac(AUTH_CONSTANTS.CRYPTO.ALGORITHM_SHA256, this.jwtSecret)
      .update(payloadB64)
      .digest(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX);
    return `${payloadB64}.${signature}`;
  }

  public verifyStateToken(state: string, expectedProvider: string): { redirectUri?: string } {
    const parts = state.split('.');
    if (parts.length !== 2) {
      throw new BadRequestError(AUTH_CONSTANTS.ERROR_MESSAGES.OAUTH_STATE_INVALID_OR_EXPIRED);
    }

    const [payloadB64, signature] = parts;
    const expectedSig = createHmac(AUTH_CONSTANTS.CRYPTO.ALGORITHM_SHA256, this.jwtSecret)
      .update(payloadB64!)
      .digest(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX);

    const sigBuf = Buffer.from(signature!, 'hex');
    const expBuf = Buffer.from(expectedSig, 'hex');

    if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigBuf, expBuf)) {
      throw new BadRequestError(AUTH_CONSTANTS.ERROR_MESSAGES.OAUTH_STATE_INVALID_OR_EXPIRED);
    }

    try {
      const payloadJson = Buffer.from(payloadB64!, 'base64url').toString('utf8');
      const payload = JSON.parse(payloadJson) as { nonce: string; timestamp: number; provider: string; redirectUri?: string };

      if (payload.provider !== expectedProvider) {
        throw new BadRequestError(AUTH_CONSTANTS.ERROR_MESSAGES.OAUTH_STATE_INVALID_OR_EXPIRED);
      }

      if (Date.now() - payload.timestamp > AUTH_CONSTANTS.OAUTH.STATE_TTL_MS) {
        throw new BadRequestError(AUTH_CONSTANTS.ERROR_MESSAGES.OAUTH_STATE_INVALID_OR_EXPIRED);
      }

      return { redirectUri: payload.redirectUri || undefined };
    } catch (err: unknown) {
      if (err instanceof BadRequestError) throw err;
      throw new BadRequestError(AUTH_CONSTANTS.ERROR_MESSAGES.OAUTH_STATE_INVALID_OR_EXPIRED);
    }
  }

  public async getAuthorizationUrl(providerName: string, redirectUri?: string): Promise<{ url: string; state: string }> {
    return withSpan('OAuthDomainService.getAuthorizationUrl', async (span) => {
      span.setAttribute('oauth.provider', providerName);
      const provider = this.providers.get(providerName);
      if (!provider) {
        throw new BadRequestError(`${AUTH_CONSTANTS.ERROR_MESSAGES.OAUTH_INVALID_PROVIDER}: ${providerName}`);
      }

      const state = this.generateStateToken(providerName, redirectUri);
      const url = await provider.getAuthorizationUrl(state, redirectUri);
      return { url, state };
    });
  }

  public async handleCallback(
    providerName: string,
    code: string,
    state: string,
    ip: string = AUTH_CONSTANTS.DEFAULTS.IP_ADDRESS,
    userAgent: string = AUTH_CONSTANTS.DEFAULTS.USER_AGENT
  ): Promise<OAuthSessionResult> {
    return withSpan('OAuthDomainService.handleCallback', async (span) => {
      span.setAttribute('oauth.provider', providerName);

      const provider = this.providers.get(providerName);
      if (!provider) {
        throw new BadRequestError(`${AUTH_CONSTANTS.ERROR_MESSAGES.OAUTH_INVALID_PROVIDER}: ${providerName}`);
      }

      const stateData = this.verifyStateToken(state, providerName);
      const profile = await provider.exchangeCodeForProfile(code, stateData.redirectUri);
      span.setAttribute('oauth.email', profile.email);

      let user = await this.resolveOrProvisionUser(profile);

      if (user.blocked) {
        throw new ForbiddenError(AUTH_CONSTANTS.ERROR_MESSAGES.USER_NOT_FOUND_OR_SUSPENDED);
      }

      const accessToken = createToken(
        user.id,
        user.email,
        {
          org_id: user.org_id,
          org_name: user.org_name,
          role: user.role as any,
        },
        AUTH_CONSTANTS.SECURITY_CONFIG.TOKEN_EXPIRE_SECONDS
      );

      const { rawToken } = await this.refreshTokenService.issueInitialRefreshToken(user.id, ip, userAgent);

      await this.repository.recordAuditLog({
        id: `aud_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
        user_id: user.id,
        org_id: user.org_id,
        event_type: AUTH_CONSTANTS.AUDIT_EVENT_OAUTH_SIGNIN,
        ip_address: ip,
        user_agent: userAgent,
        timestamp_ms: Date.now(),
      });

      return {
        accessToken,
        tokenType: 'Bearer',
        expiresIn: AUTH_CONSTANTS.SECURITY_CONFIG.TOKEN_EXPIRE_SECONDS,
        refreshToken: rawToken,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          org_id: user.org_id,
          org_name: user.org_name,
          role: user.role,
          email_verified: Boolean(user.email_verified),
        },
      };
    });
  }

  private async resolveOrProvisionUser(profile: FederatedUserProfile) {
    const existingIdentity = await this.repository.findFederatedIdentity(profile.provider, profile.provider_subject_id);

    if (existingIdentity) {
      const user = await this.repository.findUserById(existingIdentity.user_id);
      if (user) return user;
    }

    const localUser = await this.repository.findUserByEmail(profile.email);

    if (localUser) {
      if (!profile.email_verified) {
        throw new ForbiddenError(AUTH_CONSTANTS.ERROR_MESSAGES.OAUTH_EMAIL_UNVERIFIED);
      }

      const now = Date.now();
      const identityRecord: FederatedIdentityRecord = {
        id: `fed_${now}_${Math.random().toString(36).substring(2, 9)}`,
        user_id: localUser.id,
        provider: profile.provider,
        provider_subject_id: profile.provider_subject_id,
        email: profile.email,
        created_at_ms: now,
        updated_at_ms: now,
      };

      await this.repository.saveFederatedIdentity(identityRecord);
      await this.repository.recordAuditLog({
        id: `aud_${now}_${Math.random().toString(36).substring(2, 9)}`,
        user_id: localUser.id,
        org_id: localUser.org_id,
        event_type: AUTH_CONSTANTS.AUDIT_EVENT_OAUTH_LINK,
        ip_address: AUTH_CONSTANTS.DEFAULTS.IP_ADDRESS,
        user_agent: AUTH_CONSTANTS.DEFAULTS.USER_AGENT,
        timestamp_ms: now,
      });

      return localUser;
    }

    const now = Date.now();
    const newUserId = `usr_${Math.random().toString(36).substring(2, 10)}`;
    const disabledPassword = `${AUTH_CONSTANTS.OAUTH.DISABLED_PASSWORD_PREFIX}${randomBytes(16).toString(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX)}`;
    let targetOrgId = `org_${Math.random().toString(36).substring(2, 10)}`;
    let targetOrgName = `${profile.name}'s Organization`;
    let targetRole: string = AUTH_CONSTANTS.DEFAULT_ADMIN_ROLE;
    let shouldCreateOrg = true;

    if (profile.email_verified && this.domainClaimService) {
      const claimedDomain = await this.domainClaimService.findVerifiedDomainForEmail(profile.email);
      if (claimedDomain) {
        const orgRecord = await this.repository.getOrganizationById(claimedDomain.org_id);
        if (orgRecord) {
          targetOrgId = claimedDomain.org_id;
          targetOrgName = orgRecord.name;
          targetRole = claimedDomain.default_role;
          shouldCreateOrg = false;
        }
      }
    }

    const newUser = {
      id: newUserId,
      email: profile.email,
      password_hash: disabledPassword,
      name: profile.name,
      org_id: targetOrgId,
      org_name: targetOrgName,
      role: targetRole as any,
      blocked: false,
      user_permissions: [AUTH_CONSTANTS.PERMISSION_ADMIN_ALL],
      email_verified: true,
    };

    if (shouldCreateOrg) {
      await this.repository.createOrganizationAndUser(newUser);
    } else {
      await this.repository.createUser(newUser);
      await this.repository.recordAuditLog({
        id: `aud_${now}_${randomBytes(4).toString(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX)}`,
        user_id: newUserId,
        org_id: targetOrgId,
        event_type: AUTH_CONSTANTS.AUDIT_EVENT_USER_AUTO_JOINED,
        ip_address: AUTH_CONSTANTS.DEFAULTS.IP_ADDRESS,
        user_agent: AUTH_CONSTANTS.DEFAULTS.USER_AGENT,
        timestamp_ms: now,
      });
    }

    const identityRecord: FederatedIdentityRecord = {
      id: `fed_${now}_${Math.random().toString(36).substring(2, 9)}`,
      user_id: newUserId,
      provider: profile.provider,
      provider_subject_id: profile.provider_subject_id,
      email: profile.email,
      created_at_ms: now,
      updated_at_ms: now,
    };

    await this.repository.saveFederatedIdentity(identityRecord);
    return newUser;
  }

  public async listLinkedIdentities(userId: string): Promise<FederatedIdentityRecord[]> {
    return withSpan('OAuthDomainService.listLinkedIdentities', async (span) => {
      span.setAttribute('user.id', userId);
      return this.repository.listFederatedIdentitiesByUserId(userId);
    });
  }

  public async unlinkIdentity(userId: string, provider: string): Promise<void> {
    return withSpan('OAuthDomainService.unlinkIdentity', async (span) => {
      span.setAttribute('user.id', userId);
      span.setAttribute('oauth.provider', provider);

      const existing = await this.repository.findFederatedIdentityByUserAndProvider(userId, provider);
      if (!existing) {
        throw new NotFoundError(AUTH_CONSTANTS.ERROR_MESSAGES.OAUTH_IDENTITY_NOT_FOUND);
      }

      const totalIdentities = await this.repository.countFederatedIdentitiesByUserId(userId);
      const user = await this.repository.findUserById(userId);

      const hasPassword = user && !user.password_hash.startsWith(AUTH_CONSTANTS.OAUTH.DISABLED_PASSWORD_PREFIX);

      if (!hasPassword && totalIdentities <= 1) {
        throw new BadRequestError(AUTH_CONSTANTS.ERROR_MESSAGES.OAUTH_UNLINK_NOT_PERMITTED);
      }

      await this.repository.deleteFederatedIdentity(userId, provider);
      await this.repository.recordAuditLog({
        id: `aud_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
        user_id: userId,
        org_id: user?.org_id || AUTH_CONSTANTS.DEFAULT_ORG_ID,
        event_type: AUTH_CONSTANTS.AUDIT_EVENT_OAUTH_UNLINK,
        ip_address: AUTH_CONSTANTS.DEFAULTS.IP_ADDRESS,
        user_agent: AUTH_CONSTANTS.DEFAULTS.USER_AGENT,
        timestamp_ms: Date.now(),
      });
    });
  }
}

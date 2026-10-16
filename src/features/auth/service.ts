/**
 * @file service.ts
 * @description Central Unified Facade for the Authentication Feature Subsystem.
 *
 * OVERALL ALGORITHM:
 * 1. Initialize sub-domain services: OrganizationDomainService, UserManagementDomainService, UserAuthDomainService,
 *    PasswordDomainService, ApiKeyDomainService, AuditLogDomainService, and NotificationDomainService.
 * 2. Delegate incoming high-level operations to dedicated domain services using hexagonal port isolation.
 * 3. Forward optional infrastructure adapters (ICachePort, AuthEventProducer, MailerPort, custom declarative rules).
 * 4. ApiKeyDomainService now receives ICachePort for instant revocation via Redis denylist.
 * 5. NotificationDomainService coordinates MailerPort for transactional email delivery.
 */

import type { AuthRepositoryPort, OrganizationRecord } from './repository';
import type { UserDsarExportPayload, BlockedDomainRecord } from '../../shared/types/auth.types';
import type {
  SignUpInput,
  SignInInput,
  ForgotPasswordInput,
  ResetPasswordInput,
  ChangePasswordInput,
  CreateApiKeyInput,
  VerifyApiKeyInput,
  CreateOrganizationInput,
  CreateUserInput,
  AuthUserRecord,
  AuditLogRecord,
  UpdateUserProfileInput,
  InviteUserInput,
  UpdateUserRoleInput,
  UpdateUserPermissionsInput,
  UpdateOrganizationInput,
  AuditLogFilter,
} from './types';
import type { ApiKeyRecord, AuthTokenPayload } from '../../shared/types/auth.types';
import type { AuthEventProducer } from '../../shared/messaging/producers/auth-event.producer';
import type { Rule } from '@chief-strategist-j/shared-infra/rules-engine';
import type { MailerPort } from '../../shared/ports/mailer.port';
import { UnauthorizedError, NotFoundError } from '../../shared/errors/auth.errors';
import { createToken } from '../../shared/utils/jwt.util';
import { OrganizationDomainService } from './services/organization.service';
import { UserManagementDomainService } from './services/user-management.service';
import { UserAuthDomainService } from './services/user-auth.service';
import { PasswordDomainService } from './services/password.service';
import { ApiKeyDomainService } from './services/api-key.service';
import { AuditLogDomainService } from './services/audit-log.service';
import { NotificationDomainService, type NotificationConfig } from './services/notification.service';
import type { ICachePort } from '../../shared/ports/cache.interface';
import type { SecurityLimitsConfig } from '../../config/env.config';
import { SessionDenylistService } from './services/session-denylist.service';
import { LoginRateLimiterService } from './services/login-rate-limiter.service';

import { TotpMfaAdapter } from '../../infra/adapters/mfa/totp-mfa.adapter';
import { MfaDomainService } from './services/mfa.service';
import { StepUpDomainService, type StepUpVerifyInput } from './services/step-up.service';
import { RefreshTokenService, type RefreshTokenResult } from './services/refresh-token.service';
import type { MfaPort, MfaSetupResult, MfaVerificationResult } from '../../shared/ports/mfa.port';

import type { BreachedPasswordDetectorPort } from '../../shared/ports/breached-password-detector.port';
import { HaveIBeenPwnedAdapter } from '../../infra/adapters/security/pwned-passwords.adapter';
import { OAuthDomainService, type OAuthSessionResult } from './services/oauth.service';
import type { PolicyEnginePort } from './ports/policy-engine.port';
import { PolicyEngineService } from './services/policy-engine.service';
import { NativePolicyEngineAdapter } from '../../infra/adapters/policy/native-policy-engine.adapter';
import type { RelationTuple, PolicyEvaluationRequest, PolicyEvaluationResult } from '../../shared/types/auth.types';
import type { OAuthProviderPort } from './ports/oauth-provider.port';
import { GoogleOAuthAdapter } from '../../infra/adapters/oauth/google-oauth.adapter';
import { GitHubOAuthAdapter } from '../../infra/adapters/oauth/github-oauth.adapter';
import type { FederatedIdentityRecord, ClaimedDomainRecord } from '../../shared/types/auth.types';
import { AUTH_CONSTANTS } from '../../shared/constants/auth.constants';
import { AUTH_CONFIG } from '../../config/env.config';
import { DomainClaimService, type ClaimDomainInput, type ClaimDomainResult, type VerifyDomainResult } from './services/domain-claim.service';
import type { DnsResolverPort } from './ports/dns-resolver.port';
import { NodeDnsAdapter } from '../../infra/adapters/dns/node-dns.adapter';
import type { GeoIpPort } from './ports/geo-ip.port';
import { ScimProvisioningService } from './services/scim-provisioning.service';
import type { CreateScimUserInput, CreateScimGroupInput, ScimUserRecord, ScimGroupRecord, ScimListResponse, ScimPatchRequest } from './ports/scim-repository.port';
import { OidcProviderService } from './services/oidc-provider.service';
import type { JwksKey, OidcTokenResponse, M2mTokenResponse, OidcUserInfoResponse } from './ports/oidc-repository.port';
import { SamlProviderService } from './services/saml-provider.service';
import type { SamlProviderRecord, RegisterSamlProviderInput, SamlLoginResult, SamlAuthResult } from './ports/saml-repository.port';
import { PasskeyService } from './services/passkey.service';
import { CustomRoleService } from './services/custom-role.service';
import { MagicLinkService } from './services/magic-link.service';
import { WebhookService, type CreateWebhookSubscriptionInput, type WebhookSubscriptionCreationResult } from './services/webhook.service';
import { BreakGlassService, type ActivateBreakGlassParams, type BreakGlassActivationResult } from './services/break-glass.service';
import type { BreakGlassSessionRecord } from '../../shared/types/auth.types';
import type { CustomRoleRecord, PermissionEvaluationResult, MagicLinkVerifyResult, WebhookSubscriptionRecord, WebhookDeliveryRecord } from '../../shared/types/auth.types';

export class AuthService {
  private readonly repo: AuthRepositoryPort;
  private readonly orgService: OrganizationDomainService;
  private readonly userService: UserManagementDomainService;
  private readonly authService: UserAuthDomainService;
  private readonly passwordService: PasswordDomainService;
  private readonly apiKeyService: ApiKeyDomainService;
  private readonly auditLogService: AuditLogDomainService;
  private readonly mfaService: MfaDomainService;
  private readonly stepUpService: StepUpDomainService;
  private readonly refreshTokenService: RefreshTokenService;
  private readonly oauthService: OAuthDomainService;
  private readonly domainClaimService: DomainClaimService;
  private readonly policyEngineService: PolicyEngineService;
  private readonly scimService: ScimProvisioningService;
  private readonly oidcService: OidcProviderService;
  private readonly samlService: SamlProviderService;
  private readonly passkeyService: PasskeyService;
  private readonly customRoleService: CustomRoleService;
  private readonly magicLinkService: MagicLinkService;
  private readonly webhookService: WebhookService;
  private readonly breakGlassService: BreakGlassService;

  constructor(
    repo: AuthRepositoryPort,
    eventProducer?: AuthEventProducer,
    cache?: ICachePort,
    securityConfig?: SecurityLimitsConfig,
    customSignInRules?: readonly Rule[],
    mailer?: MailerPort,
    notificationConfig?: NotificationConfig,
    mfaPort?: MfaPort,
    breachedPasswordDetector?: BreachedPasswordDetectorPort,
    dnsResolver?: DnsResolverPort,
    geoIpPort?: GeoIpPort,
    policyEnginePort?: PolicyEnginePort,
  ) {
    this.repo = repo;
    this.scimService = new ScimProvisioningService(repo);
    this.oidcService = new OidcProviderService(repo, AUTH_CONFIG.oidc);
    this.samlService = new SamlProviderService(repo, AUTH_CONFIG.saml);
    this.passkeyService = new PasskeyService(repo);
    this.customRoleService = new CustomRoleService(repo);
    this.magicLinkService = new MagicLinkService(repo);
    this.webhookService = new WebhookService(repo, AUTH_CONFIG.webhook);
    this.breakGlassService = new BreakGlassService(repo);


    const policyEngine = policyEnginePort ?? new NativePolicyEngineAdapter(repo);
    this.policyEngineService = new PolicyEngineService(policyEngine, repo);

    const notificationService = mailer
      ? new NotificationDomainService(mailer, notificationConfig ?? { from: 'noreply@auth.local' })
      : undefined;

    const isBreachedCheckEnabled = securityConfig?.breachedPassword?.enabled ?? (process.env.NODE_ENV !== 'test');
    const breachedDetector = breachedPasswordDetector ?? (isBreachedCheckEnabled ? new HaveIBeenPwnedAdapter({
      baseUrl: securityConfig?.breachedPassword?.baseUrl ?? 'https://api.pwnedpasswords.com/range',
      timeoutMs: securityConfig?.breachedPassword?.timeoutMs ?? 1500,
      userAgent: securityConfig?.breachedPassword?.userAgent ?? 'llm-observability-auth/1.0.0',
    }) : undefined);

    const resolver = dnsResolver ?? new NodeDnsAdapter();
    this.domainClaimService = new DomainClaimService(repo, resolver);

    this.orgService = new OrganizationDomainService(repo);
    this.userService = new UserManagementDomainService(repo, notificationService);
    const denylistService = cache ? new SessionDenylistService(cache, securityConfig?.sessionDenylist) : undefined;
    const rateLimiterService = new LoginRateLimiterService(securityConfig?.rateLimit, cache);
    this.authService = new UserAuthDomainService(
      repo,
      eventProducer,
      denylistService,
      rateLimiterService,
      customSignInRules,
      notificationService,
      breachedDetector,
      geoIpPort,
    );
    this.passwordService = new PasswordDomainService(repo, notificationService, breachedDetector);
    this.apiKeyService = new ApiKeyDomainService(repo, cache);
    this.auditLogService = new AuditLogDomainService(repo);
    const mfa = mfaPort ?? new TotpMfaAdapter();
    this.mfaService = new MfaDomainService(repo, mfa);
    this.stepUpService = new StepUpDomainService(repo, mfa);
    this.refreshTokenService = new RefreshTokenService(repo);


    const googleAdapter = new GoogleOAuthAdapter(AUTH_CONFIG.oauth.google);
    const githubAdapter = new GitHubOAuthAdapter(AUTH_CONFIG.oauth.github);
    const providers = new Map<string, OAuthProviderPort>([
      [googleAdapter.providerName, googleAdapter],
      [githubAdapter.providerName, githubAdapter],
    ]);
    this.oauthService = new OAuthDomainService(providers, repo, this.refreshTokenService, AUTH_CONFIG.jwt.secret, this.domainClaimService);
  }


  async issueInitialRefreshToken(userId: string, ip?: string, userAgent?: string): Promise<string> {
    const res = await this.refreshTokenService.issueInitialRefreshToken(userId, ip, userAgent);
    return res.rawToken;
  }

  async rotateRefreshToken(rawToken: string, ip?: string, userAgent?: string): Promise<RefreshTokenResult> {
    return this.refreshTokenService.rotateRefreshToken(rawToken, ip, userAgent);
  }

  async issueReauthToken(userId: string, input: StepUpVerifyInput): Promise<{ reauthToken: string; expiresInSeconds: number }> {
    return this.stepUpService.issueReauthToken(userId, input);
  }

  assertStepUp(userId: string, reauthToken?: string): void {
    this.stepUpService.assertStepUpToken(userId, reauthToken);
  }

  async setupMfa(userId: string): Promise<MfaSetupResult> {
    return this.mfaService.setupMfa(userId);
  }

  async verifyAndEnableMfa(userId: string, code: string): Promise<MfaVerificationResult> {
    return this.mfaService.verifyAndEnableMfa(userId, code);
  }

  async challengeMfa(
    mfaToken: string,
    codeOrRecoveryCode: string
  ): Promise<{ token: string; user: { id: string; email: string; organization_id: string; role: string }; usedRecoveryCode: boolean }> {
    return this.mfaService.challengeMfa(mfaToken, codeOrRecoveryCode);
  }

  async regenerateRecoveryCodes(userId: string, totpCode: string): Promise<{ recoveryCodes: string[] }> {
    return this.mfaService.regenerateRecoveryCodes(userId, totpCode);
  }

  async listOrganizations(userId: string): Promise<OrganizationRecord[]> {
    return this.orgService.listOrganizations(userId);
  }

  async getOrganization(orgId: string): Promise<OrganizationRecord> {
    return this.orgService.getOrganization(orgId);
  }

  async createOrganization(input: CreateOrganizationInput, creatorUserId?: string): Promise<{ id: string; name: string; slug: string }> {
    return this.orgService.createOrganization(input, creatorUserId);
  }

  async updateOrganization(orgId: string, input: UpdateOrganizationInput): Promise<OrganizationRecord> {
    return this.orgService.updateOrganization(orgId, input);
  }

  async deleteOrganization(orgId: string): Promise<void> {
    return this.orgService.deleteOrganization(orgId);
  }

  async switchOrganization(userId: string, targetOrgId: string, currentToken: string): Promise<{ token: string; payload: AuthTokenPayload }> {
    return this.orgService.switchOrganization(userId, targetOrgId, currentToken);
  }

  async listUsers(orgId: string): Promise<AuthUserRecord[]> {
    return this.userService.listUsers(orgId);
  }

  async getUserById(userId: string): Promise<AuthUserRecord> {
    return this.userService.getUserById(userId);
  }

  async getMyProfile(userId: string): Promise<AuthUserRecord> {
    return this.userService.getMyProfile(userId);
  }

  async updateMyProfile(userId: string, input: UpdateUserProfileInput): Promise<AuthUserRecord> {
    return this.userService.updateMyProfile(userId, input);
  }

  async inviteUser(input: InviteUserInput, orgId: string, orgName: string): Promise<AuthUserRecord> {
    return this.userService.inviteUser(input, orgId, orgName);
  }

  async updateUserRole(userId: string, input: UpdateUserRoleInput): Promise<void> {
    return this.userService.updateUserRole(userId, input);
  }

  async getUserPermissions(userId: string): Promise<string[]> {
    return this.userService.getUserPermissions(userId);
  }

  async updateUserPermissions(userId: string, input: UpdateUserPermissionsInput): Promise<void> {
    return this.userService.updateUserPermissions(userId, input);
  }

  async createUser(input: CreateUserInput): Promise<AuthUserRecord> {
    return this.userService.createUser(input);
  }

  async blockUser(userId: string): Promise<void> {
    return this.userService.blockUser(userId);
  }

  async unblockUser(userId: string): Promise<void> {
    return this.userService.unblockUser(userId);
  }

  async deleteUser(userId: string): Promise<void> {
    return this.userService.deleteUser(userId);
  }

  async shredUserPii(userId: string): Promise<{ success: boolean; shreddedAt: string }> {
    return this.userService.shredUserPii(userId);
  }

  async signUp(input: SignUpInput): Promise<{ token: string; payload: AuthTokenPayload; user: AuthUserRecord }> {
    return this.authService.signUp(input);
  }

  async signIn(input: SignInInput): Promise<{ token: string; payload: AuthTokenPayload; user: AuthUserRecord }> {
    return this.authService.signIn(input);
  }

  async resolveRiskChallenge(
    challengeToken: string,
    verificationCode: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<{ token: string; payload: AuthTokenPayload; user: AuthUserRecord }> {
    return this.authService.resolveRiskChallenge(challengeToken, verificationCode, ipAddress, userAgent);
  }

  async signOut(token: string): Promise<void> {
    return this.authService.signOut(token);
  }

  async validateSession(token: string): Promise<AuthTokenPayload> {
    return this.authService.validateSession(token);
  }

  async forgotPassword(input: ForgotPasswordInput): Promise<{ resetToken: string }> {
    return this.passwordService.forgotPassword(input);
  }

  async resetPassword(input: ResetPasswordInput): Promise<void> {
    return this.passwordService.resetPassword(input);
  }

  async changePassword(userId: string, input: ChangePasswordInput): Promise<void> {
    return this.passwordService.changePassword(userId, input);
  }

  async generateApiKey(input: CreateApiKeyInput): Promise<{ rawKey: string; keyRecord: ApiKeyRecord }> {
    return this.apiKeyService.generateApiKey(input);
  }

  async listApiKeys(orgId: string): Promise<ApiKeyRecord[]> {
    return this.apiKeyService.listApiKeys(orgId);
  }

  async verifyApiKey(input: VerifyApiKeyInput): Promise<{ valid: boolean; record: ApiKeyRecord; authorized: boolean }> {
    return this.apiKeyService.verifyApiKey(input);
  }

  async revokeApiKey(keyId: string): Promise<void> {
    return this.apiKeyService.revokeApiKey(keyId);
  }

  async updateApiKeyAllowlist(keyId: string, ipAllowlist: readonly string[]): Promise<{ key_id: string; org_id: string; ip_allowlist: string[]; rate_quota_rpm: number | null } | null> {
    return this.apiKeyService.updateAllowlist(keyId, ipAllowlist);
  }

  async getApiKeyMeta(keyId: string): Promise<{ key_id: string; org_id: string; ip_allowlist: string[]; rate_quota_rpm: number | null; anomaly_flag: boolean } | null> {
    return this.apiKeyService.getApiKeyMeta(keyId);
  }

  async verifyEmail(token: string): Promise<void> {
    return this.authService.verifyEmail(token);
  }

  async resendVerificationEmail(email: string): Promise<void> {
    return this.authService.resendVerificationEmail(email);
  }

  async fetchUserAuditLogs(userId: string, filters?: AuditLogFilter): Promise<AuditLogRecord[]> {
    return this.auditLogService.fetchUserAuditLogs(userId, filters);
  }

  async purgeExpiredSoftDeletes(): Promise<number> {
    return this.auditLogService.purgeExpiredSoftDeletes();
  }

  getSystemPermissions(): string[] {
    return this.apiKeyService.getSystemPermissions();
  }

  async exportUserData(userId: string): Promise<UserDsarExportPayload> {
    return this.userService.exportUserData(userId);
  }

  async listUserSessions(userId: string, currentFamilyId?: string): Promise<Array<{
    id: string;
    ip_address?: string;
    user_agent?: string;
    created_at: string;
    last_active_at: string;
    is_current: boolean;
  }>> {
    return this.refreshTokenService.listUserSessions(userId, currentFamilyId);
  }

  async revokeUserSession(userId: string, targetFamilyId: string): Promise<void> {
    return this.refreshTokenService.revokeUserSession(userId, targetFamilyId);
  }

  async revokeOtherUserSessions(userId: string, currentFamilyId: string): Promise<number> {
    return this.refreshTokenService.revokeOtherUserSessions(userId, currentFamilyId);
  }

  async getOAuthAuthorizationUrl(provider: string, redirectUri?: string): Promise<{ url: string; state: string }> {
    return this.oauthService.getAuthorizationUrl(provider, redirectUri);
  }

  async handleOAuthCallback(provider: string, code: string, state: string, ip?: string, userAgent?: string): Promise<OAuthSessionResult> {
    return this.oauthService.handleCallback(provider, code, state, ip, userAgent);
  }

  async listLinkedOAuthIdentities(userId: string): Promise<FederatedIdentityRecord[]> {
    return this.oauthService.listLinkedIdentities(userId);
  }

  async unlinkOAuthIdentity(userId: string, provider: string): Promise<void> {
    return this.oauthService.unlinkIdentity(userId, provider);
  }

  async claimDomain(orgId: string, input: ClaimDomainInput): Promise<ClaimDomainResult> {
    return this.domainClaimService.claimDomain(orgId, input);
  }

  async verifyDomain(domainId: string, orgId: string): Promise<VerifyDomainResult> {
    return this.domainClaimService.verifyDomain(domainId, orgId);
  }

  async listClaimedDomains(orgId: string): Promise<ClaimedDomainRecord[]> {
    return this.domainClaimService.listClaimedDomains(orgId);
  }

  async updateDomainSettings(
    domainId: string,
    orgId: string,
    patch: { auto_join_enabled?: boolean; default_role?: string },
  ): Promise<ClaimedDomainRecord> {
    return this.domainClaimService.updateDomainSettings(domainId, orgId, patch);
  }

  async deleteClaimedDomain(domainId: string, orgId: string): Promise<void> {
    return this.domainClaimService.deleteClaimedDomain(domainId, orgId);
  }

  async listBlockedDomains(): Promise<BlockedDomainRecord[]> {
    return this.repo.listBlockedDomains();
  }

  async addBlockedDomain(record: { domain: string; category?: string; reason?: string }): Promise<BlockedDomainRecord> {
    const domainName = this.domainClaimService.normalizeDomain(record.domain);
    const now = Date.now();
    const blockedRecord: BlockedDomainRecord = {
      domain_name: domainName,
      category: record.category || AUTH_CONSTANTS.DOMAIN_CLAIM.CATEGORY_FREEMAIL,
      reason: record.reason || null,
      created_at_ms: now,
      updated_at_ms: now,
    };
    await this.repo.saveBlockedDomain(blockedRecord);
    return blockedRecord;
  }

  async removeBlockedDomain(rawDomain: string): Promise<void> {
    const domainName = this.domainClaimService.normalizeDomain(rawDomain);
    await this.repo.deleteBlockedDomain(domainName);
  }

  async evaluatePolicy(
    orgId: string,
    request: PolicyEvaluationRequest,
  ): Promise<PolicyEvaluationResult> {
    return this.policyEngineService.evaluatePolicy(orgId, request);
  }

  async createRelation(
    orgId: string,
    payload: {
      subject_type: string;
      subject_id: string;
      relation: string;
      object_type: string;
      object_id: string;
      conditions?: Record<string, unknown>;
      expires_at_ms?: number;
      granted_by?: string;
    },
  ): Promise<RelationTuple> {
    return this.policyEngineService.createRelation(orgId, payload);
  }

  async deleteRelation(
    orgId: string,
    payload: {
      subject_type: string;
      subject_id: string;
      relation: string;
      object_type: string;
      object_id: string;
    },
  ): Promise<boolean> {
    return this.policyEngineService.deleteRelation(orgId, payload);
  }

  async listRelations(
    orgId: string,
    filter?: {
      subject_type?: string;
      subject_id?: string;
      relation?: string;
      object_type?: string;
      object_id?: string;
    },
  ): Promise<readonly RelationTuple[]> {
    return this.policyEngineService.listRelations(orgId, filter);
  }

  async authenticateScimBearer(tokenHeader?: string): Promise<string> {
    return this.scimService.authenticateScimBearer(tokenHeader);
  }

  async getScimServiceProviderConfig(): Promise<Record<string, unknown>> {
    return this.scimService.getServiceProviderConfig();
  }

  async createScimUser(orgId: string, input: CreateScimUserInput): Promise<ScimUserRecord> {
    return this.scimService.createUser(orgId, input);
  }

  async getScimUser(orgId: string, userId: string): Promise<ScimUserRecord> {
    return this.scimService.getUser(orgId, userId);
  }

  async listScimUsers(orgId: string, filter?: string, startIndex?: number, count?: number): Promise<ScimListResponse<ScimUserRecord>> {
    return this.scimService.listUsers(orgId, filter, startIndex, count);
  }

  async patchScimUser(orgId: string, userId: string, patch: ScimPatchRequest): Promise<ScimUserRecord> {
    return this.scimService.patchUser(orgId, userId, patch);
  }

  async deleteScimUser(orgId: string, userId: string): Promise<void> {
    return this.scimService.deleteUser(orgId, userId);
  }

  async createScimGroup(orgId: string, input: CreateScimGroupInput): Promise<ScimGroupRecord> {
    return this.scimService.createGroup(orgId, input);
  }

  async getScimGroup(orgId: string, groupId: string): Promise<ScimGroupRecord> {
    return this.scimService.getGroup(orgId, groupId);
  }

  async listScimGroups(orgId: string, filter?: string, startIndex?: number, count?: number): Promise<ScimListResponse<ScimGroupRecord>> {
    return this.scimService.listGroups(orgId, filter, startIndex, count);
  }

  async patchScimGroup(orgId: string, groupId: string, patch: ScimPatchRequest): Promise<ScimGroupRecord> {
    return this.scimService.patchGroup(orgId, groupId, patch);
  }

  async deleteScimGroup(orgId: string, groupId: string): Promise<void> {
    return this.scimService.deleteGroup(orgId, groupId);
  }

  async getOpenIdConfiguration(): Promise<Record<string, unknown>> {
    return this.oidcService.getOpenIdConfiguration();
  }

  async getOidcJwks(): Promise<{ keys: ReadonlyArray<JwksKey> }> {
    return this.oidcService.getJwks();
  }

  async rotateSigningKey(params?: { alg?: 'EdDSA' | 'RS256'; gracePeriodMs?: number }): Promise<{ newKey: SigningKeyRecord; gracePeriodMs: number }> {
    return this.oidcService.keyRotationService.rotateKey(params);
  }

  async revokeSigningKey(kid: string, reason: string): Promise<void> {
    return this.oidcService.keyRotationService.revokeKey(kid, reason);
  }

  async verifySignedJwt(token: string): Promise<{ header: Record<string, any>; payload: Record<string, any> }> {
    return this.oidcService.keyRotationService.verifyJwt(token);
  }

  async createOAuthAuthorizationCode(params: {
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
    return this.oidcService.createAuthorizationCode(params);
  }

  async exchangeOAuthCodeForTokens(params: {
    grant_type: string;
    client_id: string;
    code: string;
    redirect_uri: string;
    code_verifier: string;
  }): Promise<OidcTokenResponse> {
    return this.oidcService.exchangeCodeForTokens(params);
  }

  async issueClientCredentialsToken(params: {
    client_id: string;
    client_secret: string;
    scope?: string;
    audience?: string;
  }): Promise<M2mTokenResponse> {
    return this.oidcService.issueClientCredentialsToken(params);
  }

  async getOidcUserInfo(userId: string): Promise<OidcUserInfoResponse> {
    return this.oidcService.getUserInfo(userId);
  }

  async getSamlSpMetadata(): Promise<string> {
    return this.samlService.getSpMetadata();
  }

  async registerSamlProvider(orgId: string, input: RegisterSamlProviderInput): Promise<SamlProviderRecord> {
    return this.samlService.registerProvider(orgId, input);
  }

  async listSamlProviders(orgId: string): Promise<ReadonlyArray<SamlProviderRecord>> {
    return this.samlService.listProviders(orgId);
  }

  async initiateSamlLogin(orgId: string, returnUrl?: string): Promise<SamlLoginResult> {
    return this.samlService.initiateLogin(orgId, returnUrl);
  }

  async consumeSamlAssertion(samlResponse: string, relayState: string): Promise<SamlAuthResult> {
    return this.samlService.consumeAssertion(samlResponse, relayState);
  }

  async startPasskeyRegistration(userId: string) {
    const user = await this.repo.findUserById(userId);
    if (!user) throw new UnauthorizedError('User not found');
    return this.passkeyService.generateRegistrationOptions(user.id, user.email, user.name);
  }

  async finishPasskeyRegistration(userId: string, input: any) {
    const user = await this.repo.findUserById(userId);
    if (!user) throw new UnauthorizedError('User not found');
    return this.passkeyService.verifyRegistrationResponse(user.id, user.org_id, input);
  }

  async startPasskeyAuthentication(email?: string) {
    return this.passkeyService.generateAuthenticationOptions(email);
  }

  async finishPasskeyAuthentication(input: any) {
    const result = await this.passkeyService.verifyAuthenticationResponse(input);
    const user = await this.repo.findUserById(result.userId);
    if (!user) throw new UnauthorizedError('User not found');
    const token = createToken(user.id, user.email, {
      org_id: user.org_id,
      org_name: user.org_name,
      role: user.role,
    });
    return {
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        org_id: user.org_id,
        org_name: user.org_name,
        role: user.role,
        user_permissions: user.user_permissions,
      },
      token,
      credential_id: result.credentialId,
    };
  }

  async listUserPasskeys(userId: string) {
    return this.passkeyService.listUserPasskeys(userId);
  }

  async deleteUserPasskey(passkeyId: string, userId: string) {
    return this.passkeyService.deletePasskey(passkeyId, userId);
  }

  async createCustomRole(
    orgId: string,
    params: Readonly<{ name: string; description?: string; permission_mask: string }>,
    creatorUserId?: string
  ): Promise<CustomRoleRecord> {
    return this.customRoleService.createCustomRole(orgId, params, creatorUserId);
  }

  async getCustomRole(id: string, orgId: string): Promise<CustomRoleRecord> {
    return this.customRoleService.getCustomRoleById(id, orgId);
  }

  async listCustomRoles(orgId: string): Promise<CustomRoleRecord[]> {
    return this.customRoleService.listCustomRoles(orgId);
  }

  async updateCustomRole(
    id: string,
    orgId: string,
    patch: Readonly<{ name?: string; description?: string; permission_mask?: string }>,
    actorUserId?: string
  ): Promise<CustomRoleRecord> {
    return this.customRoleService.updateCustomRole(id, orgId, patch, actorUserId);
  }

  async deleteCustomRole(id: string, orgId: string, actorUserId?: string): Promise<void> {
    return this.customRoleService.deleteCustomRole(id, orgId, actorUserId);
  }

  async assignUserCustomRoles(
    orgId: string,
    userId: string,
    roleIds: readonly string[],
    actorUserId?: string
  ): Promise<void> {
    return this.customRoleService.assignUserRoles(orgId, userId, roleIds, actorUserId);
  }

  async evaluateUserPermissions(
    orgId: string,
    userId: string,
    requiredPermissions: readonly string[]
  ): Promise<PermissionEvaluationResult> {
    return this.customRoleService.evaluateUserPermissions(orgId, userId, requiredPermissions);
  }

  async sendMagicLink(
    email: string,
    redirectUrl?: string,
    context?: { requestIp?: string; userAgent?: string }
  ): Promise<{ message: string; rawToken?: string }> {
    return this.magicLinkService.sendMagicLink(email, redirectUrl, context);
  }

  async verifyMagicLink(rawToken: string): Promise<MagicLinkVerifyResult> {
    return this.magicLinkService.verifyMagicLink(rawToken);
  }

  async consumeMagicLink(
    rawToken: string,
    context?: { requestIp?: string }
  ): Promise<{ token: string; user: AuthUserRecord; redirectUrl?: string | null }> {
    const consumed = await this.magicLinkService.consumeMagicLink(rawToken, context);
    const user = await this.repo.findUserById(consumed.userId);
    if (!user) {
      throw new NotFoundError('User not found');
    }
    const { token } = this.authService.issueTokenAndPayload(user);
    return {
      token,
      user,
      redirectUrl: consumed.redirectUrl,
    };
  }

  async createWebhookSubscription(
    input: CreateWebhookSubscriptionInput
  ): Promise<WebhookSubscriptionCreationResult> {
    return this.webhookService.createSubscription(input);
  }

  async listWebhookSubscriptions(orgId: string): Promise<WebhookSubscriptionRecord[]> {
    return this.webhookService.listSubscriptions(orgId);
  }

  async getWebhookSubscription(id: string, orgId: string): Promise<WebhookSubscriptionRecord | null> {
    return this.webhookService.getSubscription(id, orgId);
  }

  async updateWebhookSubscription(
    id: string,
    orgId: string,
    patch: { target_url?: string; subscribed_events?: readonly string[]; active?: boolean }
  ): Promise<WebhookSubscriptionRecord | null> {
    return this.webhookService.updateSubscription(id, orgId, patch);
  }

  async deleteWebhookSubscription(id: string, orgId: string): Promise<boolean> {
    return this.webhookService.deleteSubscription(id, orgId);
  }

  async listWebhookDeliveries(subscriptionId: string, orgId: string): Promise<WebhookDeliveryRecord[]> {
    return this.webhookService.listDeliveries(subscriptionId, orgId);
  }

  async activateBreakGlass(params: ActivateBreakGlassParams): Promise<BreakGlassActivationResult> {
    return this.breakGlassService.activate(params);
  }

  async verifyBreakGlassToken(token: string): Promise<BreakGlassSessionRecord> {
    return this.breakGlassService.verifyToken(token);
  }

  async terminateBreakGlass(params: { sessionId: string; terminatedBy: string; reason: string; orgId?: string }): Promise<BreakGlassSessionRecord> {
    return this.breakGlassService.terminate(params);
  }

  async listActiveBreakGlassSessions(orgId?: string): Promise<BreakGlassSessionRecord[]> {
    return this.breakGlassService.listActive(orgId);
  }
}





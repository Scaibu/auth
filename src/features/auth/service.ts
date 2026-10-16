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
import { OrganizationDomainService } from './services/organization.service';
import { UserManagementDomainService } from './services/user-management.service';
import { UserAuthDomainService } from './services/user-auth.service';
import { ApiKeyDomainService } from './services/api-key.service';
import { AuditLogDomainService } from './services/audit-log.service';
import { NotificationDomainService, type NotificationConfig } from './services/notification.service';
import type { ICachePort } from '../../shared/ports/cache.interface';
import type { SecurityLimitsConfig } from '../../config/env.config';

import { StepUpDomainService, type StepUpVerifyInput } from './services/step-up.service';

import type { PolicyEnginePort } from './ports/policy-engine.port';
import { PolicyEngineService } from './services/policy-engine.service';
import { NativePolicyEngineAdapter } from '../../infra/adapters/policy/native-policy-engine.adapter';
import type { RelationTuple, PolicyEvaluationRequest, PolicyEvaluationResult } from '../../shared/types/auth.types';
import type { ClaimedDomainRecord } from '../../shared/types/auth.types';
import { AUTH_CONSTANTS } from '../../shared/constants/auth.constants';
import { AUTH_CONFIG } from '../../config/env.config';
import { DomainClaimService, type ClaimDomainInput, type ClaimDomainResult, type VerifyDomainResult } from './services/domain-claim.service';
import type { DnsResolverPort } from './ports/dns-resolver.port';
import { NodeDnsAdapter } from '../../infra/adapters/dns/node-dns.adapter';
import type { GeoIpPort } from './ports/geo-ip.port';
import { CustomRoleService } from './services/custom-role.service';
import { WebhookService, type CreateWebhookSubscriptionInput, type WebhookSubscriptionCreationResult } from './services/webhook.service';
import { BreakGlassService, type ActivateBreakGlassParams, type BreakGlassActivationResult } from './services/break-glass.service';
import { HoneytokenService } from './services/honeytoken.service';
import { WormAuditDomainService } from './services/worm-audit.service';
import type { BreakGlassSessionRecord } from '../../shared/types/auth.types';
import type { CustomRoleRecord, PermissionEvaluationResult, WebhookSubscriptionRecord, WebhookDeliveryRecord } from '../../shared/types/auth.types';

import { KeycloakApiAdapter, KeycloakJwtVerifier } from '../../infra/adapters/keycloak';

export class AuthService {
  private readonly orgService: OrganizationDomainService;
  private readonly userService: UserManagementDomainService;
  private readonly authService: UserAuthDomainService;
  private readonly apiKeyService: ApiKeyDomainService;
  private readonly auditLogService: AuditLogDomainService;
  private readonly stepUpService: StepUpDomainService;
  private readonly domainClaimService: DomainClaimService;
  private readonly policyEngineService: PolicyEngineService;
  private readonly customRoleService: CustomRoleService;
  private readonly webhookService: WebhookService;
  private readonly breakGlassService: BreakGlassService;
  public readonly honeytokenService: HoneytokenService;
  public readonly wormAuditService: WormAuditDomainService;
  public readonly keycloakApi: KeycloakApiAdapter;
  public readonly keycloakVerifier: KeycloakJwtVerifier;

  public readonly repo: AuthRepositoryPort;
  public readonly cache?: ICachePort;

  constructor(
    repo: AuthRepositoryPort,
    eventProducer?: AuthEventProducer,
    cache?: ICachePort,
    _securityConfig?: SecurityLimitsConfig,
    customSignInRules?: readonly Rule[],
    mailer?: MailerPort,
    notificationConfig?: NotificationConfig,
    dnsResolver?: DnsResolverPort,
    geoIpPort?: GeoIpPort,
    policyEnginePort?: PolicyEnginePort,
  ) {
    this.repo = repo;
    this.cache = cache;
    this.customRoleService = new CustomRoleService(repo);
    this.webhookService = new WebhookService(repo, AUTH_CONFIG.webhook);
    this.breakGlassService = new BreakGlassService(repo);
    this.honeytokenService = new HoneytokenService(repo, cache, eventProducer);
    this.wormAuditService = new WormAuditDomainService(repo);

    const policyEngine = policyEnginePort ?? new NativePolicyEngineAdapter(repo);
    this.policyEngineService = new PolicyEngineService(policyEngine, repo);

    const notificationService = mailer
      ? new NotificationDomainService(mailer, notificationConfig ?? { from: 'noreply@auth.local' })
      : undefined;

    const resolver = dnsResolver ?? new NodeDnsAdapter();
    this.domainClaimService = new DomainClaimService(repo, resolver);

    this.orgService = new OrganizationDomainService(repo);
    this.userService = new UserManagementDomainService(repo, notificationService);
    this.authService = new UserAuthDomainService(
      repo,
      eventProducer,
      customSignInRules,
      notificationService,
      geoIpPort,
    );
    this.apiKeyService = new ApiKeyDomainService(repo, cache);
    this.auditLogService = new AuditLogDomainService(repo);
    this.stepUpService = new StepUpDomainService(repo);
    this.keycloakApi = new KeycloakApiAdapter();
    this.keycloakVerifier = new KeycloakJwtVerifier();
  }


  async issueReauthToken(userId: string, input: StepUpVerifyInput): Promise<{ reauthToken: string; expiresInSeconds: number }> {
    return this.stepUpService.issueReauthToken(userId, input);
  }

  assertStepUp(userId: string, reauthToken?: string): void {
    this.stepUpService.assertStepUpToken(userId, reauthToken);
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
    const keycloakResponse = await this.keycloakApi.signInWithPassword(input.email, input.password);
    const payload = this.keycloakVerifier.verifyToken(keycloakResponse.access_token);
    let user = await this.repo.findUserByEmail(input.email);
    if (!user) {
      user = {
        id: payload.sub,
        email: input.email,
        name: payload.email.split('@')[0] || 'User',
        password_hash: 'keycloak_managed',
        org_id: payload.org.org_id,
        org_name: payload.org.org_name,
        role: payload.org.role,
        blocked: false,
        user_permissions: (payload.org as any).permissions ?? [],
      };
    }
    return { token: keycloakResponse.access_token, payload, user };
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
    try {
      await this.keycloakApi.signOut(token);
    } catch {
      try {
        await this.keycloakApi.revokeToken(token);
      } catch {
        // Fallback for mock/internal tokens
      }
    }
  }

  async validateSession(token: string): Promise<AuthTokenPayload> {
    return this.keycloakVerifier.verifyToken(token);
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

  async handleKeycloakEvent(event: {
    type?: string;
    userId?: string;
    realmId?: string;
    details?: Record<string, unknown>;
  }): Promise<{ processed: boolean; action: string }> {
    const eventType = (event.type || '').toUpperCase();
    const targetUserId = event.userId || (event.details?.userId as string);

    if (!targetUserId) {
      return { processed: false, action: 'ignored_missing_user_id' };
    }

    if (this.cache) {
      await this.cache.set(`auth:revoked_user:${targetUserId}`, '1', 86400 * 1000);
    }

    if (eventType === 'USER_DELETE' || eventType === 'DELETE' || eventType.includes('DELETE')) {
      await this.repo.deleteUser(targetUserId).catch(() => {});
      return { processed: true, action: 'user_deleted' };
    }

    if (
      eventType === 'USER_UPDATE' ||
      eventType === 'USER_DISABLE' ||
      eventType.includes('DISABLE') ||
      eventType === 'LOGOUT'
    ) {
      await this.repo.blockUser(targetUserId).catch(() => {});
      return { processed: true, action: 'user_blocked' };
    }

    return { processed: true, action: 'token_denylisted' };
  }

  async reconcileUserStatus(userId: string): Promise<{ synced: boolean; active: boolean }> {
    const user = await this.repo.findUserById(userId);
    if (!user) {
      return { synced: false, active: false };
    }

    if (this.cache) {
      const revoked = await this.cache.get(`auth:revoked_user:${userId}`);
      if (revoked && !user.blocked) {
        await this.repo.blockUser(userId);
        return { synced: true, active: false };
      }
    }

    return { synced: true, active: !user.blocked };
  }
}





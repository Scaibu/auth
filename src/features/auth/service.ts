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
import type { MfaPort, MfaSetupResult, MfaVerificationResult } from '../../shared/ports/mfa.port';

export class AuthService {
  private readonly orgService: OrganizationDomainService;
  private readonly userService: UserManagementDomainService;
  private readonly authService: UserAuthDomainService;
  private readonly passwordService: PasswordDomainService;
  private readonly apiKeyService: ApiKeyDomainService;
  private readonly auditLogService: AuditLogDomainService;
  private readonly mfaService: MfaDomainService;
  private readonly stepUpService: StepUpDomainService;

  constructor(
    repo: AuthRepositoryPort,
    eventProducer?: AuthEventProducer,
    cache?: ICachePort,
    securityConfig?: SecurityLimitsConfig,
    customSignInRules?: readonly Rule[],
    mailer?: MailerPort,
    notificationConfig?: NotificationConfig,
    mfaPort?: MfaPort,
  ) {
    const notificationService = mailer
      ? new NotificationDomainService(mailer, notificationConfig ?? { from: 'noreply@auth.local' })
      : undefined;

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
    );
    this.passwordService = new PasswordDomainService(repo, notificationService);
    this.apiKeyService = new ApiKeyDomainService(repo, cache);
    this.auditLogService = new AuditLogDomainService(repo);
    const mfa = mfaPort ?? new TotpMfaAdapter();
    this.mfaService = new MfaDomainService(repo, mfa);
    this.stepUpService = new StepUpDomainService(repo, mfa);
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

  async signUp(input: SignUpInput): Promise<{ token: string; payload: AuthTokenPayload; user: AuthUserRecord }> {
    return this.authService.signUp(input);
  }

  async signIn(input: SignInInput): Promise<{ token: string; payload: AuthTokenPayload; user: AuthUserRecord }> {
    return this.authService.signIn(input);
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
}

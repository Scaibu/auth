/**
 * @file user-auth.service.ts
 * @description Core Domain Service for User Sign-Up and Session Validation.
 * Authentication, token issuance, MFA, password lifecycle, and session revocation are
 * fully delegated to Keycloak. This service handles:
 *   - Self-hosted sign-up (org + user creation, audit log)
 *   - Session validation stub (Keycloak JWT verification is upstream via KeycloakJwtVerifier middleware)
 *   - Risk challenge resolution (adaptive risk scoring on login events)
 */

import type { AuthRepositoryPort } from '../repository';
import type { SignUpInput, AuthUserRecord } from '../types';
import type { AuthTokenPayload } from '../../../shared/types/auth.types';
import type { AuthEventProducer } from '../../../shared/messaging/producers/auth-event.producer';
import { SignUpInputSchema } from '../schema/auth.schema';
import {
  OrgAlreadyExistsError,
  ValidationError,
  InvalidChallengeTokenError,
  InvalidCredentialsError,
} from '../../../shared/errors/auth.errors';
import { hashPassword } from '../../../shared/utils/argon2.util';
import { createToken, verifyToken } from '../../../shared/utils/jwt.util';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { withSpan } from '../../../infra/tracing/tracer';
import { normalizeString } from '../../../shared/utils/string.util';
import {
  computeBlindIndex,
  encryptEnvelope,
  generateUserDek,
  encryptUserDek,
} from '../../../shared/utils/envelope-encryption.util';
import { AUTH_CONFIG } from '../../../config/env.config';
import { resolveRules, type Rule } from '@chief-strategist-j/shared-infra/rules-engine';
import { trace } from '@chief-strategist-j/shared-infra';
import {
  DEFAULT_SIGN_UP_RULES,
  DEFAULT_SIGN_UP_ERROR_REGISTRY,
  type AuthErrorFactory,
} from '../rules/auth.rules';
import type { NotificationDomainService } from './notification.service';
import type { GeoIpPort } from '../ports/geo-ip.port';
import { AdaptiveRiskService } from './adaptive-risk.service';

export class UserAuthDomainService {
  private readonly signUpRules: readonly Rule[];
  private readonly signUpErrorRegistry: ReadonlyMap<string, AuthErrorFactory>;
  private readonly riskService: AdaptiveRiskService;

  constructor(
    private readonly repo: AuthRepositoryPort,
    private readonly eventProducer?: AuthEventProducer,
    _customSignInRules: readonly Rule[] = [],
    public readonly notificationService?: NotificationDomainService,
    private readonly geoIpPort?: GeoIpPort,
    riskService?: AdaptiveRiskService,
  ) {
    this.signUpRules = DEFAULT_SIGN_UP_RULES;
    this.signUpErrorRegistry = DEFAULT_SIGN_UP_ERROR_REGISTRY;
    this.riskService = riskService ?? new AdaptiveRiskService();
  }


  async signUp(input: SignUpInput): Promise<{ token: string; payload: AuthTokenPayload; user: AuthUserRecord }> {
    const validated = SignUpInputSchema.parse(input);
    const email = normalizeString(validated.email, 'lower');
    const orgName = normalizeString(validated.organization_name);
    const name = normalizeString(validated.name);

    const existingUser = await this.repo.findUserByEmail(email);
    const evalCtx: Readonly<Record<string, unknown>> = Object.freeze({
      email,
      userExists: Boolean(existingUser),
      isPasswordBreached: false,
    });

    const resolved = await resolveRules(this.signUpRules, evalCtx);
    const deniedList = Array.isArray(resolved)
      ? resolved.filter((r) => r && r.effect === 'deny')
      : [];

    if (deniedList.length > 0) {
      const topDenial = deniedList[0]!;
      const errorFactory = this.signUpErrorRegistry.get(topDenial.id);
      throw errorFactory ? errorFactory(evalCtx) : new ValidationError('Sign up rejected');
    }


    const passwordHash = await withSpan('Argon2id Password Hash', async (span) => {
      span.setAttribute('crypto.algorithm', 'argon2id');
      return hashPassword(validated.password);
    });

    const masterKey = {
      kid: AUTH_CONFIG.encryption.masterKeyId,
      key: Buffer.from(AUTH_CONFIG.encryption.masterKey, 'hex'),
    };
    const orgId = this.generateEntityId('org');
    const userId = this.generateEntityId('usr');
    const userDek = generateUserDek();
    const encryptedUserDek = encryptUserDek(userDek, masterKey);

    const blindIndex = computeBlindIndex(email, AUTH_CONFIG.encryption.blindIndexKey);
    const emailEncrypted = encryptEnvelope(email, masterKey, { orgId, fieldName: 'email' });
    const nameEncrypted = encryptEnvelope(name, masterKey, { orgId, fieldName: 'name' });
    userDek.fill(0);

    const userRecord: AuthUserRecord = {
      id: userId,
      email,
      password_hash: passwordHash,
      name,
      org_id: orgId,
      org_name: orgName,
      role: validated.role ?? AUTH_CONSTANTS.ROLE_ADMIN,
      blocked: false,
      user_permissions: [AUTH_CONSTANTS.PERMISSION_ADMIN_ALL],
      name_encrypted: nameEncrypted,
      email_encrypted: emailEncrypted,
      email_blind_index: blindIndex,
    };

    try {
      await this.repo.createOrganizationAndUser(userRecord);
      await this.repo.saveUserEncryptionKey({
        id: this.generateEntityId('ukey'),
        user_id: userRecord.id,
        org_id: userRecord.org_id,
        kid: masterKey.kid,
        encrypted_dek: encryptedUserDek,
      });
    } catch (err: unknown) {
      if (err instanceof Error && err.message.includes('Organization name already exists')) {
        throw new OrgAlreadyExistsError(orgName);
      }
      throw err;
    }

    const { token, payload } = this.issueTokenAndPayload(userRecord);

    this.safePublishEventAsync(() =>
      this.eventProducer?.publishUserSignedUp({
        userId: userRecord.id,
        email: userRecord.email,
        orgId: userRecord.org_id,
      }),
    );

    return { token, payload, user: userRecord };
  }

  async resolveRiskChallenge(
    challengeToken: string,
    verificationCode: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<{ token: string; payload: AuthTokenPayload; user: AuthUserRecord }> {
    const verified = this.riskService.verifyChallengeToken(challengeToken);
    if (!verified) {
      throw new InvalidChallengeTokenError();
    }

    if (verificationCode !== AUTH_CONSTANTS.RISK.DEFAULT_VERIFICATION_CODE) {
      throw new InvalidCredentialsError();
    }

    const user = await this.repo.findUserById(verified.userId);
    if (!user || user.blocked) {
      throw new InvalidCredentialsError();
    }

    const { token, payload } = this.issueTokenAndPayload(user);
    const ip = ipAddress || '0.0.0.0';
    const currentTelemetry = this.geoIpPort
      ? await this.geoIpPort.lookup(ip)
      : { ip, isDatacenter: false };
    const deviceFingerprint = this.riskService.generateDeviceFingerprint(userAgent);

    await this.recordAudit(
      AUTH_CONSTANTS.AUDIT_EVENT_RISK_CHALLENGE_RESOLVED,
      user.id,
      user.org_id,
      ipAddress,
      userAgent,
    );

    // Log login location for risk scoring continuity (retained table: auth_login_history)
    await this.repo.recordLoginHistory({
      id: `lh_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
      userId: user.id,
      ipAddress: ip,
      latitude: (currentTelemetry as any).latitude,
      longitude: (currentTelemetry as any).longitude,
      asn: (currentTelemetry as any).asn,
      isDatacenter: Boolean(currentTelemetry.isDatacenter),
      deviceFingerprint,
      riskScore: verified.riskScore,
      createdAtMs: Date.now(),
    });

    return { token, payload, user };
  }


  private generateEntityId(prefix: string): string {
    return `${prefix}_${Math.random().toString(36).substring(2, 9)}`;
  }

  issueTokenAndPayload(user: AuthUserRecord): { token: string; payload: AuthTokenPayload } {
    const token = createToken(user.id, user.email, {
      org_id: user.org_id,
      org_name: user.org_name,
      role: user.role,
    });
    return { token, payload: verifyToken(token) };
  }

  private async recordAudit(
    eventType: string,
    userId: string,
    orgId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    await this.repo.recordAuditLog({
      id: this.generateEntityId('audit'),
      user_id: userId,
      org_id: orgId,
      event_type: eventType,
      ip_address: ipAddress || '0.0.0.0',
      user_agent: userAgent || 'unknown',
      timestamp_ms: Date.now(),
    });
  }

  private executeAsync(fn: () => Promise<unknown>): void {
    Promise.resolve()
      .then(fn)
      .catch((err: unknown) => {
        const span = trace.getActiveSpan();
        if (span && err instanceof Error) {
          span.recordException(err);
        }
      });
  }

  private safePublishEventAsync(publishFn: () => Promise<unknown> | undefined): void {
    this.executeAsync(async () => {
      await publishFn();
    });
  }

  /** @deprecated Email verification is now handled by Keycloak required actions. Retained as no-op for compatibility. */
  async verifyEmail(_tokenValue: string): Promise<void> {
    // Keycloak handles email verification via VERIFY_EMAIL required action.
  }

  /** @deprecated Resend verification is now triggered via Keycloak Admin API executeActionsEmail. */
  async resendVerificationEmail(_email: string): Promise<void> {
    // Keycloak handles resend via /auth/admin/realms/{realm}/users/{id}/execute-actions-email
  }
}

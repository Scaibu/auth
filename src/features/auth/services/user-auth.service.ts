/**
 * @file user-auth.service.ts
 * @description Core Domain Service for User Authentication, Sign-Up, Sign-Out, and Session Lifecycle.
 * Implements prioritized fail-fast pipeline, non-blocking side-effects, declarative rules engine integration,
 * and centralized domain error handling.
 *
 * OVERALL ALGORITHM:
 * 1. Sign-In Pipeline:
 *    a. Normalize inputs (IP, email) and check rate limits. If rate limited, fail immediately with AccountLockedError
 *       or RateLimitExceededError before querying database or calculating CPU-heavy cryptographic hashes.
 *    b. Evaluate pre-authentication declarative rules (e.g. firewall or domain restrictions) with early exit.
 *    c. Fetch user record from database. If not found, asynchronously track failure and throw InvalidCredentialsError.
 *    d. Check user blocked state. If blocked, fail immediately with UserBlockedError.
 *    e. Verify password hash using Argon2id with OpenTelemetry span tracing. If invalid, asynchronously track failure
 *       and throw InvalidCredentialsError.
 *    f. Issue scoped JWT token and payload.
 *    g. Dispatch secondary side-effects (success counters, audit logs, Kafka events) asynchronously without blocking response.
 * 2. Sign-Up Pipeline:
 *    a. Normalize inputs and validate schema.
 *    b. Verify user uniqueness via declarative rules engine with safe array checks.
 *    c. Hash password with Argon2id, persist organization and user records with duplicate name catch handling.
 *    d. Issue scoped JWT and dispatch sign-up event asynchronously.
 * 3. Sign-Out Pipeline:
 *    a. Invalidate JTI in Redis denylist with remaining TTL and add raw token to database denylist.
 *    b. Record sign-out audit log asynchronously.
 * 4. Validate Session Pipeline:
 *    a. Verify JWT signature and expiration.
 *    b. Check distributed Redis and database denylist statuses and evaluate session rules with safe array checks.
 */

import type { AuthRepositoryPort } from '../repository';
import type { SignUpInput, SignInInput, AuthUserRecord } from '../types';
import type { AuthTokenPayload } from '../../../shared/types/auth.types';
import type { AuthEventProducer } from '../../../shared/messaging/producers/auth-event.producer';
import { SignUpInputSchema, SignInInputSchema } from '../schema/auth.schema';
import {
  AccountLockedError,
  RateLimitExceededError,
  InvalidCredentialsError,
  UserBlockedError,
  OrgAlreadyExistsError,
  ValidationError,
} from '../../../shared/errors/auth.errors';
import { hashPassword, verifyPassword } from '../../../shared/utils/argon2.util';
import { createToken, verifyToken, generateMfaChallengeToken } from '../../../shared/utils/jwt.util';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { withSpan } from '../../../infra/tracing/tracer';
import { normalizeString } from '../../../shared/utils/string.util';
import type { SessionDenylistService } from './session-denylist.service';
import type { LoginRateLimiterService, LoginRateLimitResult } from './login-rate-limiter.service';
import {
  computeBlindIndex,
  encryptEnvelope,
  generateUserDek,
  encryptUserDek,
  encryptWithDek,
} from '../../../shared/utils/envelope-encryption.util';
import { AUTH_CONFIG } from '../../../config/env.config';
import { resolveRules, type Rule } from '@chief-strategist-j/shared-infra/rules-engine';
import { trace } from '@chief-strategist-j/shared-infra';
import {
  DEFAULT_SIGN_IN_RULES,
  DEFAULT_SIGN_IN_ERROR_REGISTRY,
  CREDENTIAL_FAILURE_RULE_IDS,
  DEFAULT_SESSION_VALIDATION_RULES,
  DEFAULT_SIGN_UP_RULES,
  DEFAULT_SIGN_UP_ERROR_REGISTRY,
  type AuthErrorFactory,
} from '../rules/auth.rules';
import type { NotificationDomainService } from './notification.service';
import { hashApiKey } from '../../../shared/utils/argon2.util';

import type { BreachedPasswordDetectorPort } from '../../../shared/ports/breached-password-detector.port';
import type { GeoIpPort } from '../ports/geo-ip.port';
import { AdaptiveRiskService } from './adaptive-risk.service';
import { HighRiskSignInBlockedError, InvalidChallengeTokenError } from '../../../shared/errors/auth.errors';

export class UserAuthDomainService {
  private readonly signInRules: readonly Rule[];
  private readonly sessionValidationRules: readonly Rule[];
  private readonly signUpRules: readonly Rule[];
  private readonly signInErrorRegistry: ReadonlyMap<string, AuthErrorFactory>;
  private readonly signUpErrorRegistry: ReadonlyMap<string, AuthErrorFactory>;
  private readonly riskService: AdaptiveRiskService;

  constructor(
    private readonly repo: AuthRepositoryPort,
    private readonly eventProducer?: AuthEventProducer,
    private readonly sessionDenylistService?: SessionDenylistService,
    private readonly rateLimiterService?: LoginRateLimiterService,
    customSignInRules: readonly Rule[] = [],
    private readonly notificationService?: NotificationDomainService,
    private readonly breachedPasswordDetector?: BreachedPasswordDetectorPort,
    private readonly geoIpPort?: GeoIpPort,
    riskService?: AdaptiveRiskService,
  ) {
    this.signInRules = Object.freeze([...DEFAULT_SIGN_IN_RULES, ...customSignInRules]);
    this.sessionValidationRules = DEFAULT_SESSION_VALIDATION_RULES;
    this.signUpRules = DEFAULT_SIGN_UP_RULES;
    this.signInErrorRegistry = DEFAULT_SIGN_IN_ERROR_REGISTRY;
    this.signUpErrorRegistry = DEFAULT_SIGN_UP_ERROR_REGISTRY;
    this.riskService = riskService ?? new AdaptiveRiskService();
  }


  async signUp(input: SignUpInput): Promise<{ token: string; payload: AuthTokenPayload; user: AuthUserRecord }> {
    const validated = SignUpInputSchema.parse(input);
    const email = normalizeString(validated.email, 'lower');
    const orgName = normalizeString(validated.organization_name);
    const name = normalizeString(validated.name);

    const isPasswordBreached = this.breachedPasswordDetector
      ? await this.breachedPasswordDetector.checkIsPasswordPwned(validated.password)
      : false;

    const existingUser = await this.repo.findUserByEmail(email);
    const evalCtx: Readonly<Record<string, unknown>> = Object.freeze({
      email,
      userExists: Boolean(existingUser),
      isPasswordBreached,
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
      await this.repo.recordPasswordHistory(userRecord.id, passwordHash);
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

    this.dispatchEmailVerificationAsync(userRecord.id, userRecord.email, userRecord.name);

    return { token, payload, user: userRecord };
  }

  async signIn(input: SignInInput): Promise<{ token: string; payload: AuthTokenPayload; user: AuthUserRecord }> {
    return withSpan('UserAuthDomainService.signIn', async (span) => {
      try {
        const validated = SignInInputSchema.parse(input);
        const ip = normalizeString(validated.ip_address) || '0.0.0.0';
        const email = normalizeString(validated.email, 'lower');

        span?.setAttribute('auth.email_domain', email.split('@')[1] ?? '');
        span?.setAttribute('auth.client_ip', ip);

        const currentTelemetry = this.geoIpPort
          ? await this.geoIpPort.lookup(ip)
          : { ip, isDatacenter: false, asn: 'AS_UNKNOWN' };

        const rateLimit = await this.checkRateLimit(ip, email, {
          asn: currentTelemetry.asn,
          isDatacenter: currentTelemetry.isDatacenter,
          telemetry: currentTelemetry,
        });
        const normalizedReason = normalizeString(rateLimit.reason, 'upper');

        if (!rateLimit.allowed) {
          span?.setAttribute('auth.rate_limit_blocked', true);
          span?.setAttribute('auth.rate_limit_reason', normalizedReason);
          span?.setAttribute('auth.geo_asn', currentTelemetry.asn ?? 'unknown');
          if (normalizedReason === AUTH_CONSTANTS.SECURITY_REASONS.ACCOUNT_LOCKED) {
            throw new AccountLockedError();
          }
          throw new RateLimitExceededError();
        }

        const preCtx: Readonly<Record<string, unknown>> = Object.freeze({
          ip,
          email,
          isAccountLocked: false,
          isRateLimited: false,
        });
        const preResolved = await resolveRules(this.signInRules, preCtx);
        const preDeniedList = Array.isArray(preResolved)
          ? preResolved.filter((r) => r && r.effect === 'deny')
          : [];

        if (preDeniedList.length > 0) {
          const topDenial = preDeniedList[0]!;
          span?.setAttribute('auth.rule_denied_id', topDenial.id);
          const errorFactory = this.signInErrorRegistry.get(topDenial.id);
          throw errorFactory ? errorFactory(preCtx) : new InvalidCredentialsError();
        }

        const user = await this.repo.findUserByEmail(email);
        if (!user) {
          span?.setAttribute('auth.user_exists', false);
          await this.recordFailure(ip, email);
          throw new InvalidCredentialsError();
        }

        span?.setAttribute('auth.user_exists', true);
        span?.setAttribute('auth.user_id', user.id);
        span?.setAttribute('auth.org_id', user.org_id);

        if (user.blocked) {
          span?.setAttribute('auth.user_blocked', true);
          throw new UserBlockedError();
        }

        const isPasswordValid = await withSpan('Argon2id Password Check', async (argonSpan) => {
          argonSpan?.setAttribute('crypto.algorithm', 'argon2id');
          return verifyPassword(validated.password, user.password_hash);
        });

        if (!isPasswordValid) {
          span?.setAttribute('auth.password_valid', false);
          await this.recordFailure(ip, email);
          throw new InvalidCredentialsError();
        }

        span?.setAttribute('auth.password_valid', true);

        const fullCtx: Readonly<Record<string, unknown>> = Object.freeze({
          ip,
          email,
          isAccountLocked: false,
          isRateLimited: false,
          userExists: true,
          isBlocked: false,
          isPasswordValid: true,
        });
        const fullResolved = await resolveRules(this.signInRules, fullCtx);
        const fullDeniedList = Array.isArray(fullResolved)
          ? fullResolved.filter((r) => r && r.effect === 'deny')
          : [];

        if (fullDeniedList.length > 0) {
          const topDenial = fullDeniedList[0]!;
          span?.setAttribute('auth.post_rule_denied_id', topDenial.id);
          if (CREDENTIAL_FAILURE_RULE_IDS.has(topDenial.id)) {
            await this.recordFailure(ip, email);
          }
          const errorFactory = this.signInErrorRegistry.get(topDenial.id);
          throw errorFactory ? errorFactory(fullCtx) : new InvalidCredentialsError();
        }

        if (user.mfa_enabled) {
          span?.setAttribute('auth.mfa_required', true);
          const mfaToken = generateMfaChallengeToken(user.id, user.email, user.org_id, user.role);
          await this.recordSuccess(ip, email);
          return {
            status: AUTH_CONSTANTS.RISK.STATUS_MFA_REQUIRED,
            mfa_required: true,
            mfa_token: mfaToken,
          } as any;
        }

        const latestLogin = await this.repo.getLatestLoginLocation(user.id);
        const riskEval = this.riskService.evaluateRisk(
          currentTelemetry,
          validated.user_agent,
          latestLogin,
        );

        span?.setAttribute('auth.risk_score', riskEval.riskScore);

        if (riskEval.isBlocked) {
          span?.setAttribute('auth.risk_blocked', true);
          await Promise.all([
            this.recordFailure(ip, email),
            this.recordAudit(
              AUTH_CONSTANTS.AUDIT_EVENT_HIGH_RISK_BLOCKED,
              user.id,
              user.org_id,
              validated.ip_address,
              validated.user_agent,
            ),
          ]);
          throw new HighRiskSignInBlockedError();
        }

        if (riskEval.requiresStepUp) {
          span?.setAttribute('auth.step_up_required', true);
          const challengeToken = this.riskService.issueChallengeToken(
            user.id,
            user.email,
            riskEval.riskScore,
            riskEval.reasons,
          );
          await Promise.all([
            this.recordAudit(
              AUTH_CONSTANTS.AUDIT_EVENT_RISK_CHALLENGE_ISSUED,
              user.id,
              user.org_id,
              validated.ip_address,
              validated.user_agent,
            ),
          ]);
          return {
            status: AUTH_CONSTANTS.RISK.STATUS_STEP_UP_REQUIRED,
            step_up_required: true,
            risk_score: riskEval.riskScore,
            reasons: riskEval.reasons,
            challenge_token: challengeToken,
          } as any;
        }

        const { token, payload } = this.issueTokenAndPayload(user);

        await Promise.all([
          this.recordSuccess(ip, email),
          this.recordAudit(
            AUTH_CONSTANTS.AUDIT_EVENT_SIGNIN,
            user.id,
            user.org_id,
            validated.ip_address,
            validated.user_agent,
          ),
          this.repo.recordLoginHistory({
            id: `lh_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
            userId: user.id,
            ipAddress: ip,
            latitude: currentTelemetry.latitude,
            longitude: currentTelemetry.longitude,
            asn: currentTelemetry.asn,
            isDatacenter: Boolean(currentTelemetry.isDatacenter),
            deviceFingerprint: riskEval.currentTelemetry.deviceFingerprint,
            riskScore: riskEval.riskScore,
            createdAtMs: Date.now(),
          }),
        ]);

        this.safePublishEventAsync(() =>
          this.eventProducer?.publishUserSignedIn({
            userId: user.id,
            email: user.email,
            orgId: user.org_id,
          }),
        );

        span?.setAttribute('auth.sign_in_success', true);
        return { token, payload, user, status: AUTH_CONSTANTS.RISK.STATUS_AUTHENTICATED } as any;
      } catch (err: unknown) {
        if (err instanceof Error) {
          span?.recordException(err);
          span?.setStatus({ code: 2, message: err.message });
        }
        throw err;
      }
    });
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

    await Promise.all([
      this.recordAudit(
        AUTH_CONSTANTS.AUDIT_EVENT_RISK_CHALLENGE_RESOLVED,
        user.id,
        user.org_id,
        ipAddress,
        userAgent,
      ),
      this.repo.recordLoginHistory({
        id: `lh_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
        userId: user.id,
        ipAddress: ip,
        latitude: currentTelemetry.latitude,
        longitude: currentTelemetry.longitude,
        asn: currentTelemetry.asn,
        isDatacenter: Boolean(currentTelemetry.isDatacenter),
        deviceFingerprint,
        riskScore: verified.riskScore,
        createdAtMs: Date.now(),
      }),
    ]);

    return { token, payload, user };
  }


  async signOut(token: string): Promise<void> {
    const normalizedToken = normalizeString(token);
    const payload = verifyToken(normalizedToken);

    if (this.sessionDenylistService && payload.jti) {
      const ttlMs = Math.max(0, payload.exp * 1000 - Date.now());
      await this.sessionDenylistService.denyToken(payload.jti, ttlMs);
    }

    await this.repo.addTokenToDenylist(normalizedToken, payload.exp * 1000);

    this.executeAsync(async () => {
      await this.recordAudit(
        AUTH_CONSTANTS.AUDIT_EVENT_SIGNOUT,
        payload.sub,
        payload.org.org_id,
        '0.0.0.0',
        'server',
      );
    });
  }

  async validateSession(token: string): Promise<AuthTokenPayload> {
    const normalizedToken = normalizeString(token);
    const payload = verifyToken(normalizedToken);

    const isRedisDenylisted = Boolean(
      this.sessionDenylistService && payload.jti
        ? await this.sessionDenylistService.isTokenDenied(payload.jti)
        : false,
    );
    const isDbDenylisted = await this.repo.isTokenDenylisted(normalizedToken);

    const evalCtx: Readonly<Record<string, unknown>> = Object.freeze({
      token: normalizedToken,
      jti: payload.jti,
      isRedisDenylisted,
      isDbDenylisted,
    });

    const resolved = await resolveRules(this.sessionValidationRules, evalCtx);
    const deniedList = Array.isArray(resolved)
      ? resolved.filter((r) => r && r.effect === 'deny')
      : [];

    if (deniedList.length > 0) {
      throw new ValidationError('Session has been invalidated');
    }

    return payload;
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

  private async checkRateLimit(
    ip: string,
    email: string,
    extraContext?: Readonly<Record<string, unknown>>
  ): Promise<LoginRateLimitResult> {
    return this.rateLimiterService
      ? await this.rateLimiterService.checkLoginAllowed(ip, email, extraContext)
      : { allowed: true };
  }

  private async recordFailure(ip: string, email: string): Promise<void> {
    if (this.rateLimiterService) {
      await this.rateLimiterService.recordLoginFailure(ip, email);
    }
  }

  private async recordSuccess(ip: string, email: string): Promise<void> {
    if (this.rateLimiterService) {
      await this.rateLimiterService.recordLoginSuccess(ip, email);
    }
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

  async verifyEmail(tokenValue: string): Promise<void> {
    const normalizedToken = normalizeString(tokenValue);
    const tokenHash = await hashApiKey(normalizedToken);
    const record = await this.repo.findEmailVerificationToken(tokenHash);

    if (!record || record.used || record.expiresAtMs < Date.now()) {
      throw new ValidationError('Invalid or expired email verification token');
    }

    await this.repo.markEmailVerified(tokenHash, record.userId);
  }

  async resendVerificationEmail(email: string): Promise<void> {
    const normalizedEmail = normalizeString(email, 'lower');
    const user = await this.repo.findUserByEmail(normalizedEmail);
    if (!user) return;

    this.dispatchEmailVerificationAsync(user.id, user.email, user.name);
  }

  private dispatchEmailVerificationAsync(userId: string, email: string, name: string): void {
    if (!this.notificationService) return;

    this.executeAsync(async () => {
      const rawToken = `evf_${Math.random().toString(36).substring(2, 15)}`;
      const tokenHash = await hashApiKey(rawToken);
      const expiresAtMs = Date.now() + 24 * 60 * 60 * 1000;

      await this.repo.saveEmailVerificationToken(tokenHash, userId, email, expiresAtMs);
      await this.notificationService!.sendEmailVerification(email, name, rawToken);
    });
  }
}

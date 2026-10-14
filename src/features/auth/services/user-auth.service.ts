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

export class UserAuthDomainService {
  private readonly signInRules: readonly Rule[];
  private readonly sessionValidationRules: readonly Rule[];
  private readonly signUpRules: readonly Rule[];
  private readonly signInErrorRegistry: ReadonlyMap<string, AuthErrorFactory>;
  private readonly signUpErrorRegistry: ReadonlyMap<string, AuthErrorFactory>;

  constructor(
    private readonly repo: AuthRepositoryPort,
    private readonly eventProducer?: AuthEventProducer,
    private readonly sessionDenylistService?: SessionDenylistService,
    private readonly rateLimiterService?: LoginRateLimiterService,
    customSignInRules: readonly Rule[] = [],
    private readonly notificationService?: NotificationDomainService,
  ) {
    this.signInRules = Object.freeze([...DEFAULT_SIGN_IN_RULES, ...customSignInRules]);
    this.sessionValidationRules = DEFAULT_SESSION_VALIDATION_RULES;
    this.signUpRules = DEFAULT_SIGN_UP_RULES;
    this.signInErrorRegistry = DEFAULT_SIGN_IN_ERROR_REGISTRY;
    this.signUpErrorRegistry = DEFAULT_SIGN_UP_ERROR_REGISTRY;
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

    const userRecord: AuthUserRecord = {
      id: this.generateEntityId('usr'),
      email,
      password_hash: passwordHash,
      name,
      org_id: this.generateEntityId('org'),
      org_name: orgName,
      role: validated.role ?? AUTH_CONSTANTS.ROLE_ADMIN,
      blocked: false,
      user_permissions: [AUTH_CONSTANTS.PERMISSION_ADMIN_ALL],
    };

    try {
      await this.repo.createOrganizationAndUser(userRecord);
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
    const validated = SignInInputSchema.parse(input);
    const ip = normalizeString(validated.ip_address) || '0.0.0.0';
    const email = normalizeString(validated.email, 'lower');

    const rateLimit = await this.checkRateLimit(ip, email);
    const normalizedReason = normalizeString(rateLimit.reason, 'upper');

    if (!rateLimit.allowed) {
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
      const errorFactory = this.signInErrorRegistry.get(topDenial.id);
      throw errorFactory ? errorFactory(preCtx) : new InvalidCredentialsError();
    }

    const user = await this.repo.findUserByEmail(email);
    if (!user) {
      await this.recordFailure(ip, email);
      throw new InvalidCredentialsError();
    }

    if (user.blocked) {
      throw new UserBlockedError();
    }

    const isPasswordValid = await withSpan('Argon2id Password Check', async (span) => {
      span.setAttribute('crypto.algorithm', 'argon2id');
      return verifyPassword(validated.password, user.password_hash);
    });

    if (!isPasswordValid) {
      await this.recordFailure(ip, email);
      throw new InvalidCredentialsError();
    }

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
      if (CREDENTIAL_FAILURE_RULE_IDS.has(topDenial.id)) {
        await this.recordFailure(ip, email);
      }
      const errorFactory = this.signInErrorRegistry.get(topDenial.id);
      throw errorFactory ? errorFactory(fullCtx) : new InvalidCredentialsError();
    }

    if (user.mfa_enabled) {
      const mfaToken = generateMfaChallengeToken(user.id, user.email, user.org_id, user.role);
      await this.recordSuccess(ip, email);
      return {
        mfa_required: true,
        mfa_token: mfaToken,
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
    ]);

    this.safePublishEventAsync(() =>
      this.eventProducer?.publishUserSignedIn({
        userId: user.id,
        email: user.email,
        orgId: user.org_id,
      }),
    );

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

  private issueTokenAndPayload(user: AuthUserRecord): { token: string; payload: AuthTokenPayload } {
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

  private async checkRateLimit(ip: string, email: string): Promise<LoginRateLimitResult> {
    return this.rateLimiterService
      ? await this.rateLimiterService.checkLoginAllowed(ip, email)
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

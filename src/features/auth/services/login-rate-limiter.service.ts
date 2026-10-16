/**
 * @file login-rate-limiter.service.ts
 * @description Enterprise Login Rate Limiting & Account Defense Service (RFC 6585, ADR 0004).
 * Driven by rules engine, outcome registries, safe collections, and string normalization.
 *
 * OVERALL ALGORITHM:
 * 1. Initialize polymorphic cache adapter (distributed Redis or fallback in-memory) and rules/registry maps.
 * 2. Normalize incoming IP and email inputs to ensure deterministic state tracking and cache keys.
 * 3. Extract effective lockout and captcha record state without branching.
 * 4. Construct immutable rule evaluation context with normalized IP, email, timestamp, and security configuration.
 * 5. Delegate evaluation to the Rules Engine to resolve active rules by priority with deny-override.
 * 6. Resolve winning decision through safe array check and Result Registry lookup.
 * 7. Expose stateful failure and success mutators for tracking failed attempts and resetting lockout.
 */

import { withSpan } from '../../../infra/tracing/tracer';
import { AUTH_CONFIG, type RateLimitConfig } from '../../../config/env.config';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { normalizeString } from '../../../shared/utils/string.util';
import { extractSubnetPrefix } from '../../../shared/utils/cidr.util';
import type { ICachePort } from '../../../shared/ports/cache.interface';
import { InMemoryCacheAdapter } from '@chief-strategist-j/shared-infra/cache';
import { resolveRules, type Rule } from '@chief-strategist-j/shared-infra/rules-engine';
import {
  DEFAULT_LOGIN_RATE_LIMIT_RULES,
  DEFAULT_LOGIN_RESULT_REGISTRY,
  DEFAULT_FALLBACK_RULE,
  type LoginRateLimitResult,
  type RuleResultResolver,
} from '../rules/login-rate-limit.rules';

export { type LoginRateLimitResult };

interface FailedRecord {
  readonly count: number;
  readonly lockedUntilMs: number;
}

export class LoginRateLimiterService {
  private readonly config: RateLimitConfig;
  private readonly cache: ICachePort;
  private readonly rules: readonly Rule[];
  private readonly resultRegistry: ReadonlyMap<string, RuleResultResolver>;
  private readonly failedAttempts: Map<string, FailedRecord> = new Map();

  constructor(
    config?: Partial<RateLimitConfig>,
    cache?: ICachePort,
    customRules: readonly Rule[] = [],
    customResolvers: ReadonlyMap<string, RuleResultResolver> = new Map(),
  ) {
    this.config = Object.freeze({
      ...AUTH_CONFIG.security.rateLimit,
      ...(config || {}),
    });
    this.cache = cache ?? new InMemoryCacheAdapter();
    this.rules = Object.freeze([...DEFAULT_LOGIN_RATE_LIMIT_RULES, ...customRules]);
    this.resultRegistry = new Map([...DEFAULT_LOGIN_RESULT_REGISTRY, ...customResolvers]);
  }

  public getRules(): readonly Rule[] {
    return this.rules;
  }

  public withRules(
    additionalRules: readonly Rule[],
    additionalResolvers?: ReadonlyMap<string, RuleResultResolver>,
  ): LoginRateLimiterService {
    return new LoginRateLimiterService(
      this.config,
      this.cache,
      [...this.rules, ...additionalRules],
      new Map([...this.resultRegistry, ...(additionalResolvers ?? [])]),
    );
  }

  public async checkLoginAllowed(
    ip: string,
    email: string,
    extraContext?: Readonly<Record<string, unknown>>,
  ): Promise<LoginRateLimitResult> {
    const normalizedIp = normalizeString(ip) || '0.0.0.0';
    const normalizedEmail = normalizeString(email, 'lower');

    return withSpan('LoginRateLimiterService.checkLoginAllowed', async (span) => {
      span.setAttribute('ip', normalizedIp);
      span.setAttribute('email', normalizedEmail);

      const now = Date.now();
      const windowMs = this.config.ipWindowMs;
      const maxAttempts = this.config.maxAttemptsPerIp;

      const record = this.getEffectiveRecord(normalizedEmail, now);
      const isAccountLocked = record.lockedUntilMs > now;
      const accountRetryAfterMs = Math.max(0, record.lockedUntilMs - now);
      const isCaptchaRequired = !isAccountLocked && record.count >= this.config.emailCaptchaThreshold;

      const asn = (extraContext?.asn as string | undefined) ?? (extraContext?.telemetry as any)?.asn ?? 'AS_UNKNOWN';
      const isDatacenter = Boolean((extraContext?.isDatacenter as boolean | undefined) ?? (extraContext?.telemetry as any)?.isDatacenter);
      const subnetPrefix = extractSubnetPrefix(normalizedIp);

      const incrFn = this.cache.incr ?? (async () => 0);
      const asnWindowMs = 300000;
      const asnKey = `ratelimit:asn:${asn}`;
      const asnAttempts = await incrFn.call(this.cache, asnKey, asnWindowMs);

      const asnLimit = isDatacenter ? 50 : 200;
      const isAsnVelocityExceeded = asnAttempts > asnLimit;
      const isDatacenterStuffingBlocked = isDatacenter && asnAttempts > 20 && isAccountLocked;

      span.setAttribute('geo.asn', asn);
      span.setAttribute('geo.is_datacenter', isDatacenter);
      span.setAttribute('security.asn_attempts', asnAttempts);
      span.setAttribute('security.subnet_prefix', subnetPrefix);

      const ruleCtx: Readonly<Record<string, unknown>> = Object.freeze({
        ...(extraContext || {}),
        ip: normalizedIp,
        email: normalizedEmail,
        asn,
        isDatacenter,
        subnetPrefix,
        asnAttempts,
        isAsnVelocityExceeded,
        isDatacenterStuffingBlocked,
        now,
        cache: this.cache,
        windowMs,
        maxAttemptsPerIp: maxAttempts,
        maxFailedPerEmail: this.config.maxFailedPerEmail,
        emailCaptchaThreshold: this.config.emailCaptchaThreshold,
        emailLockoutMs: this.config.emailLockoutMs,
        isAccountLocked,
        accountRetryAfterMs,
        accountRetryAfterSeconds: Math.ceil(accountRetryAfterMs / 1000),
        isCaptchaRequired,
        failedAttemptsCount: record.count,
      });

      const resolved = await resolveRules(this.rules, ruleCtx);
      const winningRule = (Array.isArray(resolved) && resolved.length > 0 ? resolved[0] : undefined) ?? DEFAULT_FALLBACK_RULE;
      span.setAttribute('rules.winning_id', winningRule.id);

      const resolver = this.resultRegistry.get(winningRule.id) ?? this.defaultResultResolver;
      return resolver(ruleCtx, winningRule);
    });
  }

  private readonly defaultResultResolver: RuleResultResolver = (ctx, rule) =>
    Object.freeze({
      allowed: rule.effect !== 'deny',
      reason: (rule as any).reason ?? AUTH_CONSTANTS.SECURITY_REASONS.SECURITY_POLICY_VIOLATION,
      retryAfterMs: ctx.windowMs as number,
      retryAfterSeconds: Math.ceil((ctx.windowMs as number) / 1000),
    });

  private getEffectiveRecord(email: string, now: number): FailedRecord {
    const raw = this.failedAttempts.get(email);
    const isExpired = Boolean(raw && raw.lockedUntilMs > 0 && now >= raw.lockedUntilMs);
    isExpired && this.failedAttempts.delete(email);
    return isExpired || !raw ? { count: 0, lockedUntilMs: 0 } : raw;
  }

  public async recordLoginSuccess(ip: string, email: string): Promise<void> {
    const normalizedIp = normalizeString(ip) || '0.0.0.0';
    const normalizedEmail = normalizeString(email, 'lower');

    return withSpan('LoginRateLimiterService.recordLoginSuccess', async (span) => {
      span.setAttribute('ip', normalizedIp);
      span.setAttribute('email', normalizedEmail);
      this.failedAttempts.delete(normalizedEmail);
    });
  }

  public async recordLoginFailure(ip: string, email: string): Promise<void> {
    const normalizedIp = normalizeString(ip) || '0.0.0.0';
    const normalizedEmail = normalizeString(email, 'lower');

    return withSpan('LoginRateLimiterService.recordLoginFailure', async (span) => {
      span.setAttribute('ip', normalizedIp);
      span.setAttribute('email', normalizedEmail);

      const record = this.failedAttempts.get(normalizedEmail) ?? { count: 0, lockedUntilMs: 0 };
      const newCount = record.count + 1;
      const lockedUntilMs =
        newCount >= this.config.maxFailedPerEmail
          ? Date.now() + this.config.emailLockoutMs
          : 0;

      this.failedAttempts.set(normalizedEmail, Object.freeze({ count: newCount, lockedUntilMs }));
    });
  }
}

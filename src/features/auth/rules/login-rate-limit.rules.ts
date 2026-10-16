/**
 * @file login-rate-limit.rules.ts
 * @description Pure declarative rules and Result Registry for Login Rate Limiting & Defense (RFC 6585, ADR 0004).
 * Evaluated via @chief-strategist-j/shared-infra/rules-engine.
 *
 * OVERALL ALGORITHM:
 * 1. Define immutable rule identifiers and priorities (IP rate limit: 100, account lockout: 90, captcha: 50, standard: 10).
 * 2. Evaluate IP attempts asynchronously using polymorphic cache increment; evaluate lockout and captcha via synchronous conditions.
 * 3. Resolve winning decision through priority-ordered evaluation where deny-override takes precedence.
 * 4. Execute corresponding resolution factory in the Result Registry without conditional branching.
 */

import type { Rule } from '@chief-strategist-j/shared-infra/rules-engine';
import type { ICachePort } from '../../../shared/ports/cache.interface';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';

export interface LoginRateLimitResult {
  readonly allowed: boolean;
  readonly reason?: typeof AUTH_CONSTANTS.SECURITY_REASONS[keyof typeof AUTH_CONSTANTS.SECURITY_REASONS] | string;
  readonly retryAfterMs?: number;
  readonly retryAfterSeconds?: number;
  readonly requiresCaptcha?: boolean;
}

export const LOGIN_RATE_LIMIT_RULE_IDS = Object.freeze({
  ASN_VELOCITY_EXCEEDED: 'login.rule.asn_velocity_exceeded',
  DATACENTER_CREDENTIAL_STUFFING_BLOCKED: 'login.rule.datacenter_credential_stuffing_blocked',
  IP_RATE_LIMIT: 'login.rule.ip_rate_limit_exceeded',
  ACCOUNT_LOCKED: 'login.rule.account_locked',
  REQUIRE_CAPTCHA: 'login.rule.require_captcha',
  ALLOW_STANDARD: 'login.rule.allow_standard_login',
} as const);

export type RuleResultResolver = (
  ctx: Readonly<Record<string, unknown>>,
  rule: Rule,
) => LoginRateLimitResult;

export const DEFAULT_LOGIN_RATE_LIMIT_RULES: readonly Rule[] = Object.freeze([
  {
    id: LOGIN_RATE_LIMIT_RULE_IDS.ASN_VELOCITY_EXCEEDED,
    name: 'Deny request if ASN velocity limit exceeded (OAT-008)',
    category: 'threat_defense',
    priority: 120,
    effect: 'deny',
    conditions: [
      {
        field: 'isAsnVelocityExceeded',
        op: 'equals',
        value: true,
      },
    ],
  },
  {
    id: LOGIN_RATE_LIMIT_RULE_IDS.DATACENTER_CREDENTIAL_STUFFING_BLOCKED,
    name: 'Deny request from cloud hosting datacenter with high stuffing velocity',
    category: 'threat_defense',
    priority: 110,
    effect: 'deny',
    conditions: [
      {
        field: 'isDatacenterStuffingBlocked',
        op: 'equals',
        value: true,
      },
    ],
  },
  {
    id: LOGIN_RATE_LIMIT_RULE_IDS.IP_RATE_LIMIT,
    name: 'Deny request if IP rate limit exceeded (RFC 6585)',
    category: 'rate_limiting',
    priority: 100,
    effect: 'deny',
    conditions: [],
    asyncCheck: async (ctx) => {
      const cache = ctx.cache as ICachePort;
      const incrFn = cache.incr ?? (async () => 0);
      const attempts = await incrFn.call(cache, `ratelimit:ip:${ctx.ip}`, ctx.windowMs as number);
      return attempts > (ctx.maxAttemptsPerIp as number);
    },
  },
  {
    id: LOGIN_RATE_LIMIT_RULE_IDS.ACCOUNT_LOCKED,
    name: 'Deny request if account is locked out after max consecutive failures',
    category: 'defense',
    priority: 90,
    effect: 'deny',
    conditions: [
      {
        field: 'isAccountLocked',
        op: 'equals',
        value: true,
      },
    ],
  },
  {
    id: LOGIN_RATE_LIMIT_RULE_IDS.REQUIRE_CAPTCHA,
    name: 'Challenge login with CAPTCHA if consecutive failures exceed threshold',
    category: 'defense',
    priority: 50,
    effect: 'allow',
    tags: ['requires_captcha'],
    conditions: [
      {
        field: 'isCaptchaRequired',
        op: 'equals',
        value: true,
      },
    ],
  },
  {
    id: LOGIN_RATE_LIMIT_RULE_IDS.ALLOW_STANDARD,
    name: 'Allow standard login attempt',
    category: 'access',
    priority: 10,
    effect: 'allow',
    conditions: [],
  },
]);

export const DEFAULT_FALLBACK_RULE: Rule = Object.freeze({
  id: 'login.rule.fallback_allow',
  name: 'Fallback Allow',
  priority: 0,
  effect: 'allow',
  conditions: [],
});

export const DEFAULT_LOGIN_RESULT_REGISTRY: ReadonlyMap<string, RuleResultResolver> = new Map<string, RuleResultResolver>([
  [
    LOGIN_RATE_LIMIT_RULE_IDS.ASN_VELOCITY_EXCEEDED,
    (ctx: Readonly<Record<string, unknown>>) =>
      Object.freeze({
        allowed: false,
        reason: AUTH_CONSTANTS.SECURITY_REASONS.ASN_VELOCITY_EXCEEDED,
        retryAfterMs: 300000,
        retryAfterSeconds: 300,
      }),
  ],
  [
    LOGIN_RATE_LIMIT_RULE_IDS.DATACENTER_CREDENTIAL_STUFFING_BLOCKED,
    () =>
      Object.freeze({
        allowed: false,
        reason: AUTH_CONSTANTS.SECURITY_REASONS.DATACENTER_TRAFFIC_BLOCKED,
        retryAfterMs: 600000,
        retryAfterSeconds: 600,
      }),
  ],
  [
    LOGIN_RATE_LIMIT_RULE_IDS.IP_RATE_LIMIT,
    (ctx: Readonly<Record<string, unknown>>) =>
      Object.freeze({
        allowed: false,
        reason: AUTH_CONSTANTS.SECURITY_REASONS.IP_RATE_LIMIT_EXCEEDED,
        retryAfterMs: ctx.windowMs as number,
        retryAfterSeconds: Math.ceil((ctx.windowMs as number) / 1000),
      }),
  ],
  [
    LOGIN_RATE_LIMIT_RULE_IDS.ACCOUNT_LOCKED,
    (ctx: Readonly<Record<string, unknown>>) =>
      Object.freeze({
        allowed: false,
        reason: AUTH_CONSTANTS.SECURITY_REASONS.ACCOUNT_LOCKED,
        retryAfterMs: ctx.accountRetryAfterMs as number,
        retryAfterSeconds: ctx.accountRetryAfterSeconds as number,
      }),
  ],
  [
    LOGIN_RATE_LIMIT_RULE_IDS.REQUIRE_CAPTCHA,
    () =>
      Object.freeze({
        allowed: true,
        requiresCaptcha: true,
      }),
  ],
  [
    LOGIN_RATE_LIMIT_RULE_IDS.ALLOW_STANDARD,
    () =>
      Object.freeze({
        allowed: true,
      }),
  ],
]);

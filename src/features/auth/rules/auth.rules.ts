/**
 * @file auth.rules.ts
 * @description Centralized declarative rules, Error Registries, and Rule Sets for User Authentication,
 * Session Validation, Sign-Up, and Authorization. Evaluated via @chief-strategist-j/shared-infra/rules-engine.
 *
 * OVERALL ALGORITHM:
 * 1. Define immutable rule identifiers and priority specifications for authentication, session revocation, and sign-up.
 * 2. Configure declarative condition objects (lockout, rate limit, existence, blocked state, password match).
 * 3. Map rule IDs directly to domain error factories via Error Registries for zero-branching error generation.
 * 4. Export immutable rule collections for execution in the shared rules evaluation engine.
 */

import type { Rule } from '@chief-strategist-j/shared-infra/rules-engine';
import {
  AccountLockedError,
  RateLimitExceededError,
  InvalidCredentialsError,
  UserBlockedError,
  UserAlreadyExistsError,
  BreachedPasswordError,
} from '../../../shared/errors/auth.errors';


export * from './login-rate-limit.rules';

export const SIGN_IN_RULE_IDS = Object.freeze({
  ACCOUNT_LOCKED: 'auth.rule.account_locked',
  RATE_LIMIT_EXCEEDED: 'auth.rule.rate_limit_exceeded',
  USER_NOT_FOUND: 'auth.rule.user_not_found',
  USER_BLOCKED: 'auth.rule.user_blocked',
  PASSWORD_MISMATCH: 'auth.rule.password_mismatch',
} as const);

export const CREDENTIAL_FAILURE_RULE_IDS: ReadonlySet<string> = new Set([
  SIGN_IN_RULE_IDS.USER_NOT_FOUND,
  SIGN_IN_RULE_IDS.PASSWORD_MISMATCH,
]);

export const DEFAULT_SIGN_IN_RULES: readonly Rule[] = Object.freeze([
  {
    id: SIGN_IN_RULE_IDS.ACCOUNT_LOCKED,
    name: 'Reject sign-in if account is locked out after consecutive failed attempts',
    category: 'security',
    priority: 100,
    effect: 'deny',
    conditions: [
      { field: 'isAccountLocked', op: 'equals', value: true },
    ],
  },
  {
    id: SIGN_IN_RULE_IDS.RATE_LIMIT_EXCEEDED,
    name: 'Reject sign-in if IP sliding-window rate limit is exceeded',
    category: 'security',
    priority: 90,
    effect: 'deny',
    conditions: [
      { field: 'isRateLimited', op: 'equals', value: true },
    ],
  },
  {
    id: SIGN_IN_RULE_IDS.USER_NOT_FOUND,
    name: 'Reject sign-in if user record does not exist',
    category: 'identity',
    priority: 80,
    effect: 'deny',
    conditions: [
      { field: 'userExists', op: 'equals', value: false },
    ],
  },
  {
    id: SIGN_IN_RULE_IDS.USER_BLOCKED,
    name: 'Reject sign-in if user account is blocked or suspended',
    category: 'account_status',
    priority: 70,
    effect: 'deny',
    conditions: [
      { field: 'isBlocked', op: 'equals', value: true },
    ],
  },
  {
    id: SIGN_IN_RULE_IDS.PASSWORD_MISMATCH,
    name: 'Reject sign-in if cryptographic password verification fails',
    category: 'credential',
    priority: 60,
    effect: 'deny',
    conditions: [
      { field: 'isPasswordValid', op: 'equals', value: false },
    ],
  },
]);

export type AuthErrorFactory = (ctx: Readonly<Record<string, unknown>>) => Error;

export const DEFAULT_SIGN_IN_ERROR_REGISTRY: ReadonlyMap<string, AuthErrorFactory> = new Map<string, AuthErrorFactory>([
  [SIGN_IN_RULE_IDS.ACCOUNT_LOCKED, () => new AccountLockedError()],
  [SIGN_IN_RULE_IDS.RATE_LIMIT_EXCEEDED, () => new RateLimitExceededError()],
  [SIGN_IN_RULE_IDS.USER_NOT_FOUND, () => new InvalidCredentialsError()],
  [SIGN_IN_RULE_IDS.USER_BLOCKED, () => new UserBlockedError()],
  [SIGN_IN_RULE_IDS.PASSWORD_MISMATCH, () => new InvalidCredentialsError()],
]);

export const SESSION_VALIDATION_RULE_IDS = Object.freeze({
  SESSION_DENIED_IN_REDIS: 'auth.rule.session_denied_in_redis',
  SESSION_DENIED_IN_DB: 'auth.rule.session_denied_in_db',
} as const);

export const DEFAULT_SESSION_VALIDATION_RULES: readonly Rule[] = Object.freeze([
  {
    id: SESSION_VALIDATION_RULE_IDS.SESSION_DENIED_IN_REDIS,
    name: 'Reject session if token JTI is revoked in Redis denylist (ADR 0004)',
    category: 'session_revocation',
    priority: 100,
    effect: 'deny',
    conditions: [
      { field: 'isRedisDenylisted', op: 'equals', value: true },
    ],
  },
  {
    id: SESSION_VALIDATION_RULE_IDS.SESSION_DENIED_IN_DB,
    name: 'Reject session if token is revoked in database token denylist',
    category: 'session_revocation',
    priority: 90,
    effect: 'deny',
    conditions: [
      { field: 'isDbDenylisted', op: 'equals', value: true },
    ],
  },
]);

export const SIGN_UP_RULE_IDS = Object.freeze({
  USER_ALREADY_EXISTS: 'auth.rule.signup_user_already_exists',
  PASSWORD_BREACHED: 'auth.rule.password_breached',
} as const);

export const DEFAULT_SIGN_UP_RULES: readonly Rule[] = Object.freeze([
  {
    id: SIGN_UP_RULE_IDS.PASSWORD_BREACHED,
    name: 'Reject sign-up if candidate password was found in public data breaches',
    category: 'security',
    priority: 110,
    effect: 'deny',
    conditions: [
      { field: 'isPasswordBreached', op: 'equals', value: true },
    ],
  },
  {
    id: SIGN_UP_RULE_IDS.USER_ALREADY_EXISTS,
    name: 'Reject sign-up if email is already registered',
    category: 'registration',
    priority: 100,
    effect: 'deny',
    conditions: [
      { field: 'userExists', op: 'equals', value: true },
    ],
  },
]);

export const DEFAULT_SIGN_UP_ERROR_REGISTRY: ReadonlyMap<string, AuthErrorFactory> = new Map<string, AuthErrorFactory>([
  [SIGN_UP_RULE_IDS.PASSWORD_BREACHED, () => new BreachedPasswordError()],
  [SIGN_UP_RULE_IDS.USER_ALREADY_EXISTS, (ctx) => new UserAlreadyExistsError(String(ctx.email ?? ''))],
]);


export interface AuthRule {
  id: string;
  category: 'authentication' | 'authorization' | 'api_key';
  priority: number;
  effect: 'allow' | 'deny';
  condition: (ctx: { role?: string; revoked?: boolean; active?: boolean }) => boolean;
}

export const AUTH_DECLARATIVE_RULES: AuthRule[] = [
  {
    id: 'RULE_DENY_REVOKED_API_KEY',
    category: 'api_key',
    priority: 100,
    effect: 'deny',
    condition: (ctx) => ctx.revoked === true,
  },
  {
    id: 'RULE_ALLOW_ADMIN_ROLE',
    category: 'authorization',
    priority: 90,
    effect: 'allow',
    condition: (ctx) => ctx.role === 'admin',
  },
  {
    id: 'RULE_ALLOW_ACTIVE_USER',
    category: 'authentication',
    priority: 50,
    effect: 'allow',
    condition: (ctx) => ctx.active !== false,
  },
];

export function evaluateAuthRules(
  rules: AuthRule[],
  ctx: { role?: string; revoked?: boolean; active?: boolean }
): { allowed: boolean; matchedRuleId: string } {
  const sorted = [...rules].sort((a, b) => b.priority - a.priority);
  for (const rule of sorted) {
    if (rule.condition(ctx)) {
      return {
        allowed: rule.effect === 'allow',
        matchedRuleId: rule.id,
      };
    }
  }
  return { allowed: false, matchedRuleId: 'RULE_DEFAULT_DENY' };
}

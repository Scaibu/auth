/**
 * @file security.config.ts
 * @description Declarative Security & Rate Limit Configuration with zero domain process.env leakage.
 *
 * OVERALL ALGORITHM:
 * 1. Define immutable contracts for RateLimitConfig and SessionDenylistConfig.
 * 2. Export deeply frozen DEFAULT_SECURITY_CONFIG baseline values.
 * 3. Read environment variable overrides with fallback to default constants in loadSecurityConfig().
 * 4. Return deeply frozen SecurityLimitsConfig instance to enforce immutability across subsystems.
 */

export interface RateLimitConfig {
  maxAttemptsPerIp: number;
  ipWindowMs: number;
  maxFailedPerEmail: number;
  emailLockoutMs: number;
  emailCaptchaThreshold: number;
}

export interface SessionDenylistConfig {
  keyPrefix: string;
  defaultTtlSeconds: number;
}

export interface BreachedPasswordConfig {
  enabled: boolean;
  baseUrl?: string;
  timeoutMs: number;
  userAgent?: string;
}

export interface SecurityLimitsConfig {
  rateLimit: RateLimitConfig;
  sessionDenylist: SessionDenylistConfig;
  breachedPassword: BreachedPasswordConfig;
}

export const DEFAULT_SECURITY_CONFIG: SecurityLimitsConfig = Object.freeze({
  rateLimit: Object.freeze({
    maxAttemptsPerIp: 10,
    ipWindowMs: 15 * 60 * 1000,
    maxFailedPerEmail: 5,
    emailLockoutMs: 15 * 60 * 1000,
    emailCaptchaThreshold: 3,
  }),
  sessionDenylist: Object.freeze({
    keyPrefix: 'auth:denylist:',
    defaultTtlSeconds: 3600,
  }),
  breachedPassword: Object.freeze({
    enabled: process.env.NODE_ENV !== 'test',
    baseUrl: 'https://api.pwnedpasswords.com/range',
    timeoutMs: 1500,
    userAgent: 'llm-observability-auth/1.0.0',
  }),
});


export function loadSecurityConfig(): SecurityLimitsConfig {
  return Object.freeze({
    rateLimit: Object.freeze({
      maxAttemptsPerIp: parseInt(
        process.env.AUTH_RATE_LIMIT_MAX_ATTEMPTS_PER_IP ||
          String(DEFAULT_SECURITY_CONFIG.rateLimit.maxAttemptsPerIp),
        10,
      ),
      ipWindowMs: parseInt(
        process.env.AUTH_RATE_LIMIT_IP_WINDOW_MS ||
          String(DEFAULT_SECURITY_CONFIG.rateLimit.ipWindowMs),
        10,
      ),
      maxFailedPerEmail: parseInt(
        process.env.AUTH_RATE_LIMIT_MAX_FAILED_PER_EMAIL ||
          String(DEFAULT_SECURITY_CONFIG.rateLimit.maxFailedPerEmail),
        10,
      ),
      emailLockoutMs: parseInt(
        process.env.AUTH_RATE_LIMIT_EMAIL_LOCKOUT_MS ||
          String(DEFAULT_SECURITY_CONFIG.rateLimit.emailLockoutMs),
        10,
      ),
      emailCaptchaThreshold: parseInt(
        process.env.AUTH_RATE_LIMIT_EMAIL_CAPTCHA_THRESHOLD ||
          String(DEFAULT_SECURITY_CONFIG.rateLimit.emailCaptchaThreshold),
        10,
      ),
    }),
    sessionDenylist: Object.freeze({
      keyPrefix:
        process.env.AUTH_SESSION_DENYLIST_KEY_PREFIX ||
        DEFAULT_SECURITY_CONFIG.sessionDenylist.keyPrefix,
      defaultTtlSeconds: parseInt(
        process.env.AUTH_SESSION_DEFAULT_TTL_SECONDS ||
          String(DEFAULT_SECURITY_CONFIG.sessionDenylist.defaultTtlSeconds),
        10,
      ),
    }),
    breachedPassword: Object.freeze({
      enabled: process.env.AUTH_BREACHED_PASSWORD_ENABLED !== undefined
        ? process.env.AUTH_BREACHED_PASSWORD_ENABLED === 'true'
        : DEFAULT_SECURITY_CONFIG.breachedPassword.enabled,
      baseUrl: process.env.AUTH_BREACHED_PASSWORD_BASE_URL || DEFAULT_SECURITY_CONFIG.breachedPassword.baseUrl,
      timeoutMs: parseInt(
        process.env.AUTH_BREACHED_PASSWORD_TIMEOUT_MS ||
          String(DEFAULT_SECURITY_CONFIG.breachedPassword.timeoutMs),
        10,
      ),
      userAgent: process.env.AUTH_BREACHED_PASSWORD_USER_AGENT || DEFAULT_SECURITY_CONFIG.breachedPassword.userAgent,
    }),
  });
}


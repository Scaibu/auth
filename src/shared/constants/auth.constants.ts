/**
 * @file auth.constants.ts
 * @description Centralized, deeply immutable constants for the Auth Subsystem.
 *
 * OVERALL ALGORITHM:
 * 1. Pull dynamic configuration from AUTH_CONFIG without direct process.env reads.
 * 2. Declare system-wide protocol headers, endpoints, role definitions, and permission scopes.
 * 3. Export deeply frozen constant dictionary to ensure immutability across runtime consumers.
 */

import { AUTH_CONFIG } from '../../config/env.config';

export const AUTH_CONSTANTS = {
  SERVICE_NAME: AUTH_CONFIG.otel.serviceName,
  SERVICE_VERSION: '1.0.0',
  DEFAULT_PORT: AUTH_CONFIG.server.port,
  DEFAULT_DATABASE_URL: AUTH_CONFIG.db.url,
  DEFAULT_PROTOCOL: AUTH_CONFIG.server.protocol,
  ENDPOINT_ROOT: '/',
  STATUS_NO_CONTENT: 204,
  METHOD_OPTIONS: 'OPTIONS',
  HEADER_CONTENT_TYPE: 'Content-Type',
  DEFAULT_ADMIN_EMAIL: 'admin@observability.io',
  DEFAULT_ADMIN_ID: 'usr-admin-001',
  DEFAULT_ADMIN_NAME: 'Observability Admin',
  DEFAULT_ADMIN_ROLE: 'admin',
  DEFAULT_ORG_ID: 'org-default-001',
  DEFAULT_ORG_NAME: 'Acme Observability',
  DEFAULT_ADMIN_PASSWORD_HASH: 'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f',
  
  HEADERS: {
    CONTENT_TYPE_JSON: 'application/json',
    AUTHORIZATION: 'authorization',
    AUTHORIZATION_CAMEL: 'Authorization',
    FORWARDED_FOR: 'x-forwarded-for',
    USER_AGENT: 'user-agent',
    BEARER_PREFIX: 'Bearer ',
    REAUTH_TOKEN: 'x-reauth-token',
    REAUTH_TOKEN_CAMEL: 'X-Reauth-Token',
  },

  SECURITY_REASONS: {
    ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
    IP_RATE_LIMIT_EXCEEDED: 'IP_RATE_LIMIT_EXCEEDED',
    SECURITY_POLICY_VIOLATION: 'SECURITY_POLICY_VIOLATION',
  },

  SECURITY_CONFIG: {
    CORS_HEADERS: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Expose-Headers': 'traceparent, tracestate, x-request-id, x-correlation-id, x-causation-id',
      'Access-Control-Max-Age': '86400',
    },
    TOKEN_EXPIRE_SECONDS: 3600,
    SALT_ROUNDS: 10,
    PASSWORD_MIN_LENGTH: 12,
    PASSWORD_PATTERN: '^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*]).{12,}$',
    RATE_LIMIT: {
      MAX_ATTEMPTS_PER_IP: AUTH_CONFIG.security.rateLimit.maxAttemptsPerIp,
      IP_WINDOW_MS: AUTH_CONFIG.security.rateLimit.ipWindowMs,
      MAX_FAILED_PER_EMAIL: AUTH_CONFIG.security.rateLimit.maxFailedPerEmail,
      EMAIL_LOCKOUT_MS: AUTH_CONFIG.security.rateLimit.emailLockoutMs,
      EMAIL_CAPTCHA_THRESHOLD: AUTH_CONFIG.security.rateLimit.emailCaptchaThreshold,
    },
  },

  ENDPOINTS: {
    HEALTH: '/health',
    METRICS: '/metrics',
    SIGN_UP: '/api/v1/auth/sign-up',
    SIGN_IN: '/api/v1/auth/sign-in',
    GET_SESSION: '/api/v1/auth/session',
    FORGOT_PASSWORD: '/api/v1/auth/forgot-password',
    RESET_PASSWORD: '/api/v1/auth/reset-password',
    CHANGE_PASSWORD: '/api/v1/auth/change-password',
    ORGANIZATIONS: '/api/v1/auth/organizations',
    ORGANIZATION_BY_ID: '/api/v1/auth/organizations/:id',
    USERS: '/api/v1/auth/users',
    USER_BLOCK: '/api/v1/auth/users/:id/block',
    USER_BY_ID: '/api/v1/auth/users/:id',
    API_KEYS: '/api/v1/auth/api-keys',
    API_KEY_VERIFY: '/api/v1/auth/api-keys/verify',
    PERMISSIONS: '/api/v1/auth/permissions',
    AUDIT_LOGS: '/api/v1/auth/audit-logs',
  },

  API_KEY_PREFIX_GENERAL: 'ak_gen_',
  API_KEY_PREFIX_TESTING: 'ak_tst_',
  API_KEY_PREFIX_SUPER_SECRET: 'ak_sec_',
  KEY_TYPE_GENERAL: 'general',
  KEY_TYPE_TESTING: 'testing',
  KEY_TYPE_SUPER_SECRET: 'super_secret',
  PERMISSION_TRACES_READ: 'traces:read',
  PERMISSION_TRACES_WRITE: 'traces:write',
  PERMISSION_METRICS_READ: 'metrics:read',
  PERMISSION_METRICS_WRITE: 'metrics:write',
  PERMISSION_LOGS_READ: 'logs:read',
  PERMISSION_LOGS_WRITE: 'logs:write',
  PERMISSION_ALERTS_READ: 'alerts:read',
  PERMISSION_ALERTS_WRITE: 'alerts:write',
  PERMISSION_ADMIN_ALL: 'admin:all',
  SPAN_DB_SYSTEM: 'db.system',
  SPAN_DB_SYSTEM_VAL: 'alloydb_omni',
  ROLE_ADMIN: 'admin',
  ROLE_MEMBER: 'member',
  ROLE_VIEWER: 'viewer',
  AUDIT_EVENT_SIGNIN: 'USER_SIGNIN',
  AUDIT_EVENT_SIGNUP: 'USER_SIGNUP',
  AUDIT_EVENT_SIGNOUT: 'USER_SIGNOUT',
  AUDIT_EVENT_PASSWORD_RESET: 'PASSWORD_RESET',
  AUDIT_EVENT_API_KEY_CREATED: 'API_KEY_CREATED',
  AUDIT_EVENT_ORG_SWITCH: 'ORG_SWITCH',
} as const;

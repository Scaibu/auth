/**
 * @file security-headers.config.ts
 * @description Declarative Security Headers and Strict CSP configuration.
 *
 * OVERALL ALGORITHM:
 * 1. Define immutable typed interfaces for SecurityHeadersConfig.
 * 2. Export deeply frozen DEFAULT_SECURITY_HEADERS_CONFIG.
 * 3. Read environment variable overrides with fallback in loadSecurityHeadersConfig().
 * 4. Return deeply frozen SecurityHeadersConfig enforcing immutability.
 */

export interface SecurityHeadersConfig {
  readonly enabled: boolean;
  readonly hsts: {
    readonly enabled: boolean;
    readonly maxAgeSeconds: number;
    readonly includeSubDomains: boolean;
    readonly preload: boolean;
  };
  readonly frameOptions: 'DENY' | 'SAMEORIGIN';
  readonly noSniff: boolean;
  readonly referrerPolicy: string;
  readonly permissionsPolicy: string;
  readonly crossOriginOpenerPolicy: string;
  readonly crossOriginResourcePolicy: string;
  readonly csp: {
    readonly enabled: boolean;
    readonly reportOnly: boolean;
    readonly baseUri: string;
    readonly objectSrc: string;
    readonly frameAncestors: string;
  };
}

export const DEFAULT_SECURITY_HEADERS_CONFIG: SecurityHeadersConfig = Object.freeze({
  enabled: true,
  hsts: Object.freeze({
    enabled: true,
    maxAgeSeconds: 63072000,
    includeSubDomains: true,
    preload: true,
  }),
  frameOptions: 'DENY',
  noSniff: true,
  referrerPolicy: 'strict-origin-when-cross-origin',
  permissionsPolicy: 'geolocation=(), camera=(), microphone=(), payment=()',
  crossOriginOpenerPolicy: 'same-origin',
  crossOriginResourcePolicy: 'same-origin',
  csp: Object.freeze({
    enabled: true,
    reportOnly: false,
    baseUri: "'none'",
    objectSrc: "'none'",
    frameAncestors: "'none'",
  }),
});

export function loadSecurityHeadersConfig(): SecurityHeadersConfig {
  const isEnabled = process.env.AUTH_SECURITY_HEADERS_ENABLED !== 'false';
  const isHstsEnabled = process.env.AUTH_SECURITY_HEADERS_HSTS_ENABLED !== 'false';
  const hstsMaxAge = process.env.AUTH_SECURITY_HEADERS_HSTS_MAX_AGE
    ? parseInt(process.env.AUTH_SECURITY_HEADERS_HSTS_MAX_AGE, 10)
    : DEFAULT_SECURITY_HEADERS_CONFIG.hsts.maxAgeSeconds;
  const isCspEnabled = process.env.AUTH_SECURITY_HEADERS_CSP_ENABLED !== 'false';
  const isCspReportOnly = process.env.AUTH_SECURITY_HEADERS_CSP_REPORT_ONLY === 'true';

  const frameOptions = process.env.AUTH_SECURITY_HEADERS_FRAME_OPTIONS === 'SAMEORIGIN'
    ? 'SAMEORIGIN'
    : DEFAULT_SECURITY_HEADERS_CONFIG.frameOptions;

  return Object.freeze({
    enabled: isEnabled,
    hsts: Object.freeze({
      enabled: isHstsEnabled,
      maxAgeSeconds: Number.isNaN(hstsMaxAge) ? DEFAULT_SECURITY_HEADERS_CONFIG.hsts.maxAgeSeconds : hstsMaxAge,
      includeSubDomains: process.env.AUTH_SECURITY_HEADERS_HSTS_INCLUDE_SUBDOMAINS !== 'false',
      preload: process.env.AUTH_SECURITY_HEADERS_HSTS_PRELOAD !== 'false',
    }),
    frameOptions,
    noSniff: process.env.AUTH_SECURITY_HEADERS_NOSNIFF !== 'false',
    referrerPolicy: process.env.AUTH_SECURITY_HEADERS_REFERRER_POLICY || DEFAULT_SECURITY_HEADERS_CONFIG.referrerPolicy,
    permissionsPolicy: process.env.AUTH_SECURITY_HEADERS_PERMISSIONS_POLICY || DEFAULT_SECURITY_HEADERS_CONFIG.permissionsPolicy,
    crossOriginOpenerPolicy: process.env.AUTH_SECURITY_HEADERS_COOP || DEFAULT_SECURITY_HEADERS_CONFIG.crossOriginOpenerPolicy,
    crossOriginResourcePolicy: process.env.AUTH_SECURITY_HEADERS_CORP || DEFAULT_SECURITY_HEADERS_CONFIG.crossOriginResourcePolicy,
    csp: Object.freeze({
      enabled: isCspEnabled,
      reportOnly: isCspReportOnly,
      baseUri: DEFAULT_SECURITY_HEADERS_CONFIG.csp.baseUri,
      objectSrc: DEFAULT_SECURITY_HEADERS_CONFIG.csp.objectSrc,
      frameAncestors: DEFAULT_SECURITY_HEADERS_CONFIG.csp.frameAncestors,
    }),
  });
}

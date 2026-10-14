/**
 * @file security-headers.engine.ts
 * @description Pure deterministic engine for synthesizing enterprise security headers with dynamic CSP nonces.
 *
 * OVERALL ALGORITHM:
 * 1. Generate 128-bit cryptographically secure base64 nonce.
 * 2. Evaluate SecurityHeadersConfig flags for HSTS, frame options, sniffing, referrer, and CSP.
 * 3. Assemble and return immutable headers dictionary and request nonce.
 */

import { randomBytes } from 'node:crypto';
import type { SecurityHeadersConfig } from '../../config/security-headers.config';
import { AUTH_CONSTANTS } from '../constants/auth.constants';

export interface SecurityHeadersOutput {
  readonly nonce: string;
  readonly headers: Readonly<Record<string, string>>;
}

export function generateCspNonce(): string {
  return randomBytes(16).toString('base64');
}

function buildHstsValue(hsts: SecurityHeadersConfig['hsts']): string {
  const directives: string[] = [
    `${AUTH_CONSTANTS.HSTS_DIRECTIVES.MAX_AGE_PREFIX}${hsts.maxAgeSeconds}`,
    hsts.includeSubDomains ? AUTH_CONSTANTS.HSTS_DIRECTIVES.INCLUDE_SUBDOMAINS : '',
    hsts.preload ? AUTH_CONSTANTS.HSTS_DIRECTIVES.PRELOAD : '',
  ];
  return directives.filter((d) => d.length > 0).join('');
}

function buildCspValue(csp: SecurityHeadersConfig['csp'], nonce: string): string {
  return [
    AUTH_CONSTANTS.CSP_DIRECTIVES.DEFAULT_SRC_SELF,
    `${AUTH_CONSTANTS.CSP_DIRECTIVES.SCRIPT_SRC_PREFIX}${nonce}${AUTH_CONSTANTS.CSP_DIRECTIVES.SCRIPT_SRC_SUFFIX}`,
    `${AUTH_CONSTANTS.CSP_DIRECTIVES.OBJECT_SRC_PREFIX}${csp.objectSrc}`,
    `${AUTH_CONSTANTS.CSP_DIRECTIVES.BASE_URI_PREFIX}${csp.baseUri}`,
    `${AUTH_CONSTANTS.CSP_DIRECTIVES.FRAME_ANCESTORS_PREFIX}${csp.frameAncestors}`,
  ].join(AUTH_CONSTANTS.CSP_DIRECTIVES.DELIMITER);
}

export function computeSecurityHeaders(
  config: SecurityHeadersConfig,
  customNonce?: string
): SecurityHeadersOutput {
  const nonce = customNonce !== undefined && customNonce.length > 0 ? customNonce : generateCspNonce();
  if (!config.enabled) {
    return {
      nonce,
      headers: Object.freeze({}),
    };
  }

  const cspHeaderKey = config.csp.reportOnly
    ? AUTH_CONSTANTS.HEADERS.CONTENT_SECURITY_POLICY_REPORT_ONLY
    : AUTH_CONSTANTS.HEADERS.CONTENT_SECURITY_POLICY;

  const entries: Array<[string, string | undefined]> = [
    [AUTH_CONSTANTS.HEADERS.STRICT_TRANSPORT_SECURITY, config.hsts.enabled ? buildHstsValue(config.hsts) : undefined],
    [AUTH_CONSTANTS.HEADERS.X_CONTENT_TYPE_OPTIONS, config.noSniff ? AUTH_CONSTANTS.HEADERS.NOSNIFF : undefined],
    [AUTH_CONSTANTS.HEADERS.X_FRAME_OPTIONS, config.frameOptions ? config.frameOptions : undefined],
    [AUTH_CONSTANTS.HEADERS.REFERRER_POLICY, config.referrerPolicy ? config.referrerPolicy : undefined],
    [AUTH_CONSTANTS.HEADERS.PERMISSIONS_POLICY, config.permissionsPolicy ? config.permissionsPolicy : undefined],
    [AUTH_CONSTANTS.HEADERS.CROSS_ORIGIN_OPENER_POLICY, config.crossOriginOpenerPolicy ? config.crossOriginOpenerPolicy : undefined],
    [AUTH_CONSTANTS.HEADERS.CROSS_ORIGIN_RESOURCE_POLICY, config.crossOriginResourcePolicy ? config.crossOriginResourcePolicy : undefined],
    [cspHeaderKey, config.csp.enabled ? buildCspValue(config.csp, nonce) : undefined],
  ];

  const headers: Record<string, string> = {};
  for (const [key, val] of entries) {
    if (val !== undefined && val.length > 0) {
      headers[key] = val;
    }
  }

  return {
    nonce,
    headers: Object.freeze(headers),
  };
}

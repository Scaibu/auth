/**
 * @file security-headers.test.ts
 * @description Comprehensive unit & integration tests for Automated Security Headers and Strict CSP (W3C CSP Level 3 / RFC 6797).
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { computeSecurityHeaders, generateCspNonce } from '../../src/shared/utils/security-headers.engine';
import { loadSecurityHeadersConfig, DEFAULT_SECURITY_HEADERS_CONFIG } from '../../src/config/security-headers.config';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AuthService } from '../../src/features/auth/service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';

describe('Automated Security Headers & Strict CSP Test Suite', () => {
  it('1. Generates 128-bit high-entropy base64 CSP nonces', () => {
    const nonce1 = generateCspNonce();
    const nonce2 = generateCspNonce();

    expect(nonce1).toBeTypeOf('string');
    expect(nonce2).toBeTypeOf('string');
    expect(nonce1).not.toBe(nonce2);
    // 16 bytes base64 encoded is 24 characters with padding
    expect(nonce1.length).toBeGreaterThanOrEqual(22);
  });

  it('2. Computes complete RFC 6797 and W3C security headers under default config', () => {
    const output = computeSecurityHeaders(DEFAULT_SECURITY_HEADERS_CONFIG, 'test_nonce_123');

    expect(output.nonce).toBe('test_nonce_123');
    const headers = output.headers;

    expect(headers['Strict-Transport-Security']).toBe('max-age=63072000; includeSubDomains; preload');
    expect(headers['X-Content-Type-Options']).toBe('nosniff');
    expect(headers['X-Frame-Options']).toBe('DENY');
    expect(headers['Referrer-Policy']).toBe('strict-origin-when-cross-origin');
    expect(headers['Permissions-Policy']).toBe('geolocation=(), camera=(), microphone=(), payment=()');
    expect(headers['Cross-Origin-Opener-Policy']).toBe('same-origin');
    expect(headers['Cross-Origin-Resource-Policy']).toBe('same-origin');

    expect(headers['Content-Security-Policy']).toContain("default-src 'self'");
    expect(headers['Content-Security-Policy']).toContain("script-src 'nonce-test_nonce_123' 'strict-dynamic'");
    expect(headers['Content-Security-Policy']).toContain("object-src 'none'");
    expect(headers['Content-Security-Policy']).toContain("base-uri 'none'");
    expect(headers['Content-Security-Policy']).toContain("frame-ancestors 'none'");
  });

  it('3. Respects CSP Report-Only configuration switch', () => {
    const reportOnlyConfig = {
      ...DEFAULT_SECURITY_HEADERS_CONFIG,
      csp: {
        ...DEFAULT_SECURITY_HEADERS_CONFIG.csp,
        reportOnly: true,
      },
    };

    const output = computeSecurityHeaders(reportOnlyConfig, 'report_nonce');
    expect(output.headers['Content-Security-Policy']).toBeUndefined();
    expect(output.headers['Content-Security-Policy-Report-Only']).toContain("script-src 'nonce-report_nonce'");
  });

  it('4. Allows operators to disable security headers completely via config toggle', () => {
    const disabledConfig = {
      ...DEFAULT_SECURITY_HEADERS_CONFIG,
      enabled: false,
    };

    const output = computeSecurityHeaders(disabledConfig);
    expect(Object.keys(output.headers).length).toBe(0);
  });

  it('5. Integrates into AuthRestV1Router and injects security headers on 200 OK responses', async () => {
    const repo = new AlloyDBOmniAuthAdapter();
    const service = new AuthService(repo);
    const router = new AuthRestV1Router(service, DEFAULT_SECURITY_HEADERS_CONFIG);

    const res = await router.route('GET', '/api/v1/auth/health');

    expect(res.statusCode).toBe(200);
    expect(res.headers).toBeDefined();
    expect(res.headers!['X-Content-Type-Options']).toBe('nosniff');
    expect(res.headers!['X-Frame-Options']).toBe('DENY');
    expect(res.headers!['Strict-Transport-Security']).toContain('max-age=63072000');
    expect(res.headers!['Content-Security-Policy']).toContain("script-src 'nonce-");
  });

  it('6. Injects security headers on 4xx / 5xx error responses to protect error payloads', async () => {
    const repo = new AlloyDBOmniAuthAdapter();
    const service = new AuthService(repo);
    const router = new AuthRestV1Router(service, DEFAULT_SECURITY_HEADERS_CONFIG);

    // Call protected endpoint without credentials to trigger 401 Unauthorized
    const res = await router.route('GET', '/api/v1/auth/users/me/export');

    expect(res.statusCode).toBe(401);
    expect(res.headers).toBeDefined();
    expect(res.headers!['X-Content-Type-Options']).toBe('nosniff');
    expect(res.headers!['X-Frame-Options']).toBe('DENY');
    expect(res.headers!['Content-Security-Policy']).toContain("script-src 'nonce-");
  });

  it('7. Generates distinct, independent nonces per sequential HTTP route invocation', async () => {
    const repo = new AlloyDBOmniAuthAdapter();
    const service = new AuthService(repo);
    const router = new AuthRestV1Router(service, DEFAULT_SECURITY_HEADERS_CONFIG);

    const res1 = await router.route('GET', '/api/v1/auth/health');
    const res2 = await router.route('GET', '/api/v1/auth/health');

    const csp1 = res1.headers!['Content-Security-Policy'];
    const csp2 = res2.headers!['Content-Security-Policy'];

    expect(csp1).not.toBe(csp2);
  });
});

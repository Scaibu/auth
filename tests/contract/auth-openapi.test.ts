/**
 * @file auth-openapi.test.ts
 * @description Contract compliance verification asserting that OpenAPI v1.yaml synchronizes
 * with endpoint constants, security schemas, API key expiration, and email verification.
 *
 * OVERALL ALGORITHM:
 * 1. Resolve path to contracts/openapi/v1.yaml specification file.
 * 2. Assert file existence and openapi version 3.0.3 compliance.
 * 3. Verify presence of all declared REST endpoints matching AUTH_ENDPOINTS enum.
 * 4. Verify presence of all security headers, error codes, and request/response schema definitions.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { AUTH_ENDPOINTS } from '../../src/shared/constants/endpoints';

describe('Auth OpenAPI Contract Compliance', () => {
  it('should verify contracts/openapi/v1.yaml exists and matches declared endpoints and schemas', () => {
    const contractPath = fs.existsSync(path.join(process.cwd(), 'contracts/openapi/v1.yaml'))
      ? path.join(process.cwd(), 'contracts/openapi/v1.yaml')
      : path.join(process.cwd(), 'packages/node/auth/contracts/openapi/v1.yaml');
    expect(fs.existsSync(contractPath)).toBe(true);

    const content = fs.readFileSync(contractPath, 'utf8');
    expect(content).toContain('openapi: 3.0.3');
    expect(content).toContain(AUTH_ENDPOINTS.SIGN_UP);
    expect(content).toContain(AUTH_ENDPOINTS.SIGN_IN);
    expect(content).toContain(AUTH_ENDPOINTS.SESSION);
    expect(content).toContain(AUTH_ENDPOINTS.FORGOT_PASSWORD);
    expect(content).toContain(AUTH_ENDPOINTS.RESET_PASSWORD);
    expect(content).toContain(AUTH_ENDPOINTS.CHANGE_PASSWORD);
    expect(content).toContain(AUTH_ENDPOINTS.API_KEYS);
    expect(content).toContain(AUTH_ENDPOINTS.API_KEYS_VERIFY);
    expect(content).toContain(AUTH_ENDPOINTS.VERIFY_EMAIL);
    expect(content).toContain(AUTH_ENDPOINTS.RESEND_VERIFICATION);
    expect(content).toContain(AUTH_ENDPOINTS.PERMISSIONS);
    expect(content).toContain(AUTH_ENDPOINTS.AUDIT_LOGS);
    expect(content).toContain(AUTH_ENDPOINTS.ADMIN_PURGE_EXPIRED);
    expect(content).toContain(AUTH_ENDPOINTS.USERS_ME_EXPORT);
    expect(content).toContain('SignUpRequest');
    expect(content).toContain('SignInRequest');
    expect(content).toContain('CreateApiKeyRequest');
    expect(content).toContain('VerifyApiKeyRequest');
    expect(content).toContain('VerifyEmailRequest');
    expect(content).toContain('ResendVerificationRequest');
    expect(content).toContain('expires_at_ms');
    expect(content).toContain('API_KEY_EXPIRED');
    expect(content).toContain('API_KEY_REVOKED');
    expect(content).toContain('X-CSRF-Token');
    expect(content).toContain('ip_address');
    expect(content).toContain('ACCOUNT_LOCKED');
    expect(content).toContain('RATE_LIMIT_EXCEEDED');
    expect(content).toContain('PASSWORD_BREACHED');
    expect(content).toContain('JTI');
    expect(content).toContain("'423'");
    expect(content).toContain("'429'");
  });
});


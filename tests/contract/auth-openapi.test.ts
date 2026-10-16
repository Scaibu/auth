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
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

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
    expect(content).toContain(AUTH_ENDPOINTS.SESSIONS);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.USER_SESSION_SUMMARY);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.SIGN_UP_REQUEST);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.SIGN_IN_REQUEST);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.CREATE_API_KEY_REQUEST);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.VERIFY_API_KEY_REQUEST);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.VERIFY_EMAIL_REQUEST);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.RESEND_VERIFICATION_REQUEST);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.EXPIRES_AT_MS);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.API_KEY_EXPIRED);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.API_KEY_REVOKED);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.X_CSRF_TOKEN);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.IP_ADDRESS);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.ACCOUNT_LOCKED);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.RATE_LIMIT_EXCEEDED);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.PASSWORD_BREACHED);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.JTI);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.STATUS_423);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.STATUS_429);

    // Zero-Trust API Key Allowlists & Quotas (ADR 0027)
    expect(content).toContain(AUTH_ENDPOINTS.API_KEY_ALLOWLIST.replace(':id', '{id}'));
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.UPDATE_API_KEY_ALLOWLIST_REQUEST);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.API_KEY_IP_DENIED);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.API_KEY_RATE_LIMIT_EXCEEDED);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.IP_ALLOWLIST);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.RATE_QUOTA_RPM);
    expect(content).toContain(AUTH_CONSTANTS.CONTRACT_SCHEMAS.CLIENT_IP);
  });
});



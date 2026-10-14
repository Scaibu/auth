/**
 * @file refresh-token-rotation.test.ts
 * @description RFC 6749 §10.4 Refresh Token Rotation & Family Reuse Detection Tests.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AuthService } from '../../src/features/auth/service';
import { UnauthorizedError } from '../../src/shared/errors/auth.errors';

describe('Refresh Token Rotation & Family Reuse Detection (RFC 6749 §10.4)', () => {
  let adapter: AlloyDBOmniAuthAdapter;
  let service: AuthService;
  const testUserId = 'usr_test_refresh_123';

  beforeEach(async () => {
    adapter = new AlloyDBOmniAuthAdapter();
    service = new AuthService(adapter);
    await adapter.createUser({
      id: testUserId,
      email: 'test_refresh@observability.local',
      password_hash: 'hash_test_123',
      name: 'Refresh Test User',
      org_id: 'org_test_123',
      org_name: 'Refresh Test Org',
      role: 'admin',
      blocked: false,
      user_permissions: ['admin:all'],
      email_verified: true,
    });
  });

  it('should successfully issue initial refresh token and rotate to generation 2', async () => {
    const rawRefreshToken = await service.issueInitialRefreshToken(testUserId, '127.0.0.1', 'Vitest-Agent');
    expect(rawRefreshToken).toMatch(/^rt_[a-f0-9]{64}$/);

    const result = await service.rotateRefreshToken(rawRefreshToken, '127.0.0.1', 'Vitest-Agent');
    expect(result.accessToken).toBeDefined();
    expect(result.refreshToken).toBeDefined();
    expect(result.refreshToken).not.toBe(rawRefreshToken);
    expect(result.expiresInSeconds).toBe(900);
  });

  it('should trigger family reuse killswitch when an already consumed refresh token is presented', async () => {
    const initialToken = await service.issueInitialRefreshToken(testUserId);
    const rotation1 = await service.rotateRefreshToken(initialToken);
    expect(rotation1.refreshToken).toBeDefined();

    await expect(service.rotateRefreshToken(initialToken)).rejects.toThrowError(
      /Token reuse detected. All sessions in this token family have been terminated/i,
    );

    await expect(service.rotateRefreshToken(rotation1.refreshToken)).rejects.toThrowError(
      /Token family has been revoked/i,
    );
  });

  it('should reject non-existent or tampered refresh tokens with UnauthorizedError', async () => {
    await expect(service.rotateRefreshToken('rt_tampered_non_existent_token_string')).rejects.toThrowError(
      UnauthorizedError,
    );
  });
});

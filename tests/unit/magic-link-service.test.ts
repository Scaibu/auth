import { describe, it, expect, beforeEach } from 'vitest';
import { MagicLinkService } from '../../src/features/auth/services/magic-link.service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { ValidationError, NotFoundError, ConflictError } from '../../src/shared/errors/auth.errors';

describe('MagicLinkService Unit Tests (ADR 0031)', () => {
  let adapter: AlloyDBOmniAuthAdapter;
  let service: MagicLinkService;

  beforeEach(async () => {
    adapter = new AlloyDBOmniAuthAdapter();
    service = new MagicLinkService(adapter);

    await adapter.createUser({
      id: 'usr_magic_test_1',
      email: 'alex.engineer@observability.io',
      name: 'Alex Engineer',
      password_hash: 'argon2id_mock_hash',
      org_id: 'org_magic_test',
      org_name: 'Observability Org',
      role: 'member',
      blocked: false,
      user_permissions: ['telemetry:read'],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
  });

  it('dispatches a magic link with a high-entropy 256-bit token', async () => {
    const res = await service.sendMagicLink(
      'alex.engineer@observability.io',
      'https://app.observability.io/dashboard',
      { requestIp: '192.0.2.1', userAgent: 'Mozilla/5.0' }
    );

    expect(res.message).toBe('If an account exists with this email address, a sign-in link has been sent.');
    expect(res.rawToken).toBeDefined();
    expect(typeof res.rawToken).toBe('string');
    expect(res.rawToken!.length).toBe(64);
  });

  it('returns generic message without leaking non-existence of email', async () => {
    const res = await service.sendMagicLink('nonexistent@observability.io');
    expect(res.message).toBe('If an account exists with this email address, a sign-in link has been sent.');
    expect(res.rawToken).toBeUndefined();
  });

  it('rejects dispatch exceeding rate limit of 3 requests per 15 minutes', async () => {
    const email = 'alex.engineer@observability.io';
    await service.sendMagicLink(email);
    await service.sendMagicLink(email);
    await service.sendMagicLink(email);

    await expect(service.sendMagicLink(email)).rejects.toThrow(ValidationError);
  });

  it('pre-flight verifies token state without consuming it (anti-scanner defense)', async () => {
    const dispatch = await service.sendMagicLink('alex.engineer@observability.io');
    const token = dispatch.rawToken!;

    const verify1 = await service.verifyMagicLink(token);
    expect(verify1.valid).toBe(true);
    expect(verify1.email).toBe('alex.engineer@observability.io');

    const verify2 = await service.verifyMagicLink(token);
    expect(verify2.valid).toBe(true);
  });

  it('atomically consumes magic link token exactly once', async () => {
    const dispatch = await service.sendMagicLink('alex.engineer@observability.io');
    const token = dispatch.rawToken!;

    const consumed = await service.consumeMagicLink(token, { requestIp: '198.51.100.4' });
    expect(consumed.userId).toBe('usr_magic_test_1');
    expect(consumed.orgId).toBe('org_magic_test');

    await expect(service.consumeMagicLink(token)).rejects.toThrow(ConflictError);

    const postVerify = await service.verifyMagicLink(token);
    expect(postVerify.valid).toBe(false);
    expect(postVerify.error).toContain('already been used');
  });

  it('supersedes older pending tokens when a user initiates a novel dispatch', async () => {
    const dispatch1 = await service.sendMagicLink('alex.engineer@observability.io');
    const token1 = dispatch1.rawToken!;

    const dispatch2 = await service.sendMagicLink('alex.engineer@observability.io');
    const token2 = dispatch2.rawToken!;

    const verify1 = await service.verifyMagicLink(token1);
    expect(verify1.valid).toBe(false);
    expect(verify1.error).toContain('superseded');

    const verify2 = await service.verifyMagicLink(token2);
    expect(verify2.valid).toBe(true);

    const consumed2 = await service.consumeMagicLink(token2);
    expect(consumed2.userId).toBe('usr_magic_test_1');
  });
});

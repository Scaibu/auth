/**
 * @file session-denylist.service.ts
 * @description Direct Redis O(1) Token Denylist Service for Instant Session Killswitch (ADR 0004).
 *
 * OVERALL ALGORITHM:
 * 1. Initialize with injected ICachePort adapter and configurable key prefix.
 * 2. Revoke token by normalizing JTI and setting key with remaining token lifetime TTL in cache.
 * 3. Validate token by normalizing JTI and checking presence of key in cache; return true if denied, false otherwise.
 */

import { withSpan } from '../../../infra/tracing/tracer';
import { AUTH_CONFIG, type SessionDenylistConfig } from '../../../config/env.config';
import type { ICachePort } from '../../../shared/ports/cache.interface';
import { normalizeString } from '../../../shared/utils/string.util';

export class SessionDenylistService {
  private readonly keyPrefix: string;

  constructor(
    private readonly cache: ICachePort,
    config?: Partial<SessionDenylistConfig>,
  ) {
    this.keyPrefix = config?.keyPrefix ?? AUTH_CONFIG.security.sessionDenylist.keyPrefix ?? 'denylist:jti:';
  }

  async denyToken(jti: string, ttlMs: number): Promise<void> {
    const normalizedJti = normalizeString(jti);
    if (!normalizedJti) return;

    return withSpan('SessionDenylistService.denyToken', async (span) => {
      span.setAttribute('token.jti', normalizedJti);
      span.setAttribute('denylist.prefix', this.keyPrefix);
      await this.cache.set(`${this.keyPrefix}${normalizedJti}`, 'true', ttlMs);
      if (this.keyPrefix !== 'denylist:jti:') {
        await this.cache.set(`denylist:jti:${normalizedJti}`, 'true', ttlMs);
      }
    });
  }

  async isTokenDenied(jti: string): Promise<boolean> {
    const normalizedJti = normalizeString(jti);
    if (!normalizedJti) return false;

    return withSpan('SessionDenylistService.isTokenDenied', async (span) => {
      span.setAttribute('token.jti', normalizedJti);
      try {
        const denied = await this.cache.exists(`${this.keyPrefix}${normalizedJti}`);
        if (denied) return true;
        if (this.keyPrefix !== 'denylist:jti:') {
          return await this.cache.exists(`denylist:jti:${normalizedJti}`);
        }
        return false;
      } catch {
        return false;
      }
    });
  }
}

/**
 * @file pwned-passwords.adapter.ts
 * @description Outbound Hexagonal Adapter for HaveIBeenPwned k-Anonymity API (NIST SP 800-63B).
 *
 * OVERALL ALGORITHM:
 * 1. Compute uppercase SHA-1 of candidate password locally in memory.
 * 2. Extract first 5 characters as k-anonymity prefix, remaining 35 characters as targetSuffix.
 * 3. Perform HTTP GET to https://api.pwnedpasswords.com/range/{prefix} with timeout budget and OpenTelemetry span.
 * 4. Scan newline-delimited response body ({suffix}:{count}) for targetSuffix.
 * 5. Return true if matched, false otherwise.
 * 6. Fail-open invariant: If upstream is down, times out, or errors, log warning and return false to preserve availability.
 */

import { createHash } from 'node:crypto';
import type { BreachedPasswordDetectorPort } from '../../../shared/ports/breached-password-detector.port';
import { withSpan } from '../../tracing/tracer';
import { httpClient } from '@chief-strategist-j/shared-infra/http';
import { SpanStatusCode } from '@chief-strategist-j/shared-infra';

export interface HaveIBeenPwnedAdapterConfig {
  readonly baseUrl: string;
  readonly timeoutMs: number;
  readonly userAgent: string;
}

export class HaveIBeenPwnedAdapter implements BreachedPasswordDetectorPort {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly userAgent: string;

  constructor(config: HaveIBeenPwnedAdapterConfig) {
    this.baseUrl = config.baseUrl;
    this.timeoutMs = config.timeoutMs;
    this.userAgent = config.userAgent;
  }

  async checkIsPasswordPwned(password: string): Promise<boolean> {
    if (!password || typeof password !== 'string') {
      return false;
    }

    return withSpan('auth.password.breach_check', async (span) => {
      span.setAttribute('security.check', 'breached_password');
      span.setAttribute('security.standard', 'NIST_SP_800_63B');

      const sha1 = createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
      const prefix = sha1.substring(0, 5);
      const targetSuffix = sha1.substring(5);

      if (!/^[0-9A-F]{5}$/.test(prefix)) {
        span.setAttribute('security.breach_check_status', 'invalid_prefix');
        return false;
      }

      span.setAttribute('security.k_anonymity_prefix', prefix);

      const url = `${this.baseUrl}/${prefix}`;
      span.setAttribute('http.url', url);

      try {
        const hostname = new URL(url).hostname;
        const result = await httpClient.get<string>(
          url,
          {
            'User-Agent': this.userAgent,
            'Add-Padding': 'true',
          },
          {
            timeoutMs: this.timeoutMs,
            allowedHosts: [hostname],
          }
        );

        if (result.status < 200 || result.status >= 300) {
          span.setAttribute('security.breach_check_status', 'upstream_error');
          span.setAttribute('http.status_code', result.status);
          return false;
        }

        const text = typeof result.data === 'string' ? result.data : JSON.stringify(result.data);
        const lines = text.split('\r\n');

        let isPwned = false;
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i]!.trim();
          if (!line) continue;
          const colonIdx = line.indexOf(':');
          const suffix = colonIdx !== -1 ? line.substring(0, colonIdx).trim() : line;
          if (suffix.toUpperCase() === targetSuffix) {
            isPwned = true;
            break;
          }
        }

        span.setAttribute('security.is_breached', isPwned);
        span.setStatus({ code: SpanStatusCode.OK });
        return isPwned;
      } catch (err: unknown) {
        if (err instanceof Error) {
          span.recordException(err);
        }
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: err instanceof Error ? err.message : 'Breach screening request failed',
        });
        span.setAttribute('security.breach_check_status', 'timeout_or_network_failure');
        span.setAttribute('security.is_breached', false);
        return false;
      }
    });
  }
}


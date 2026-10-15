import crypto from 'node:crypto';
import type { AuthRepositoryPort } from '../repository';
import type { MagicLinkRecord, MagicLinkVerifyResult } from '../../../shared/types/auth.types';
import { ValidationError, NotFoundError, ConflictError } from '../../../shared/errors/auth.errors';
import { withSpan } from '@chief-strategist-j/shared-infra';

export class MagicLinkService {
  constructor(private readonly repository: AuthRepositoryPort) {}

  private hashToken(rawToken: string): string {
    return crypto.createHash('sha256').update(rawToken).digest('hex');
  }

  async sendMagicLink(
    email: string,
    redirectUrl?: string,
    context?: { requestIp?: string; userAgent?: string }
  ): Promise<{ message: string; rawToken?: string }> {
    return withSpan('MagicLinkService.sendMagicLink', async (span: any) => {
      try {
        const normalizedEmail = email.trim().toLowerCase();
        span?.setAttribute('auth.email_domain', normalizedEmail.split('@')[1] ?? '');
        span?.setAttribute('auth.has_redirect_url', Boolean(redirectUrl));
        span?.setAttribute('auth.has_ip', Boolean(context?.requestIp));

        const now = Date.now();
        const fifteenMinutesAgo = now - 15 * 60 * 1000;

        const emailRateCount = await this.repository.countRecentMagicLinksByEmail(normalizedEmail, fifteenMinutesAgo);
        span?.setAttribute('auth.email_recent_requests', emailRateCount);
        if (emailRateCount >= 3) {
          throw new ValidationError('Too many magic link requests for this email address. Please wait 15 minutes.');
        }

        if (context?.requestIp) {
          const ipRateCount = await this.repository.countRecentMagicLinksByIp(context.requestIp, fifteenMinutesAgo);
          span?.setAttribute('auth.ip_recent_requests', ipRateCount);
          if (ipRateCount >= 10) {
            throw new ValidationError('Too many magic link requests from your network. Please wait 15 minutes.');
          }
        }

        const user = await this.repository.findUserByEmail(normalizedEmail);
        if (!user) {
          span?.setAttribute('auth.user_exists', false);
          return { message: 'If an account exists with this email address, a sign-in link has been sent.' };
        }

        span?.setAttribute('auth.user_exists', true);
        span?.setAttribute('auth.user_id', user.id);
        span?.setAttribute('auth.org_id', user.org_id);

        await this.repository.supersedePendingMagicLinks(user.org_id, user.id, now);

        const rawToken = crypto.randomBytes(32).toString('hex');
        const tokenHash = this.hashToken(rawToken);
        const id = `mlink_${crypto.randomUUID()}`;
        const publicId = `pub_${id}`;
        const expiresAtMs = now + 15 * 60 * 1000;

        const userAgentHash = context?.userAgent
          ? crypto.createHash('sha256').update(context.userAgent).digest('hex')
          : undefined;

        const record: MagicLinkRecord = {
          id,
          public_id: publicId,
          org_id: user.org_id,
          user_id: user.id,
          email: normalizedEmail,
          token_hash: tokenHash,
          redirect_url: redirectUrl ?? null,
          request_ip: context?.requestIp ?? null,
          user_agent_hash: userAgentHash ?? null,
          version: 1,
          expires_at_ms: expiresAtMs,
          created_at_ms: now,
          updated_at_ms: now,
        };

        await this.repository.saveMagicLink(record);
        span?.setAttribute('auth.magic_link_id', id);

        return {
          message: 'If an account exists with this email address, a sign-in link has been sent.',
          rawToken,
        };
      } catch (err: unknown) {
        if (err instanceof Error) {
          span?.recordException(err);
          span?.setStatus({ code: 2, message: err.message });
        }
        throw err;
      }
    });
  }

  async verifyMagicLink(rawToken: string): Promise<MagicLinkVerifyResult> {
    return withSpan('MagicLinkService.verifyMagicLink', async (span: any) => {
      try {
        const trimmed = rawToken.trim();
        if (!trimmed || trimmed.length < 32) {
          span?.setAttribute('auth.verify_result', 'invalid_format');
          return { valid: false, error: 'Invalid token format' };
        }

        const tokenHash = this.hashToken(trimmed);
        const record = await this.repository.findMagicLinkByHash(tokenHash);
        if (!record) {
          span?.setAttribute('auth.verify_result', 'not_found');
          return { valid: false, error: 'Magic link not found or invalid' };
        }

        span?.setAttribute('auth.magic_link_id', record.id);
        span?.setAttribute('auth.user_id', record.user_id);
        span?.setAttribute('auth.org_id', record.org_id);

        if (record.consumed_at_ms) {
          span?.setAttribute('auth.verify_result', 'already_used');
          return { valid: false, error: 'Magic link has already been used' };
        }

        if (record.superseded_at_ms) {
          span?.setAttribute('auth.verify_result', 'superseded');
          return { valid: false, error: 'Magic link has been superseded by a newer request' };
        }

        const now = Date.now();
        if (record.expires_at_ms <= now) {
          span?.setAttribute('auth.verify_result', 'expired');
          return { valid: false, error: 'Magic link has expired' };
        }

        span?.setAttribute('auth.verify_result', 'valid');
        return {
          valid: true,
          email: record.email,
          redirect_url: record.redirect_url,
          expires_at_ms: record.expires_at_ms,
        };
      } catch (err: unknown) {
        if (err instanceof Error) {
          span?.recordException(err);
          span?.setStatus({ code: 2, message: err.message });
        }
        throw err;
      }
    });
  }

  async consumeMagicLink(
    rawToken: string,
    context?: { requestIp?: string }
  ): Promise<{ userId: string; orgId: string; email: string; redirectUrl?: string | null }> {
    return withSpan('MagicLinkService.consumeMagicLink', async (span: any) => {
      try {
        const trimmed = rawToken.trim();
        if (!trimmed || trimmed.length < 32) {
          throw new ValidationError('Valid token is required');
        }

        const tokenHash = this.hashToken(trimmed);
        const record = await this.repository.findMagicLinkByHash(tokenHash);
        if (!record) {
          throw new NotFoundError('Magic link not found');
        }

        span?.setAttribute('auth.magic_link_id', record.id);
        span?.setAttribute('auth.user_id', record.user_id);
        span?.setAttribute('auth.org_id', record.org_id);

        if (record.consumed_at_ms) {
          span?.setAttribute('auth.consume_failure_reason', 'already_used');
          throw new ConflictError('Magic link has already been used');
        }

        if (record.superseded_at_ms) {
          span?.setAttribute('auth.consume_failure_reason', 'superseded');
          throw new ConflictError('Magic link has been superseded by a newer request');
        }

        const now = Date.now();
        if (record.expires_at_ms <= now) {
          span?.setAttribute('auth.consume_failure_reason', 'expired');
          throw new ValidationError('Magic link has expired');
        }

        const consumed = await this.repository.consumeMagicLink(tokenHash, now, context?.requestIp);
        if (!consumed) {
          span?.setAttribute('auth.consume_failure_reason', 'atomic_race_conflict');
          throw new ConflictError('Failed to consume magic link; it may have already been used');
        }

        span?.setAttribute('auth.consumed_success', true);
        span?.setAttribute('auth.consumed_at_ms', now);

        return {
          userId: record.user_id,
          orgId: record.org_id,
          email: record.email,
          redirectUrl: record.redirect_url,
        };
      } catch (err: unknown) {
        if (err instanceof Error) {
          span?.recordException(err);
          span?.setStatus({ code: 2, message: err.message });
        }
        throw err;
      }
    });
  }
}

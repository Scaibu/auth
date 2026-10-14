import { createHash, randomBytes } from 'crypto';
import { withSpan } from '../../../infra/tracing/tracer';
import type { AuthRepositoryPort } from '../repository';
import { UnauthorizedError, NotFoundError } from '../../../shared/errors/auth.errors';
import { createToken } from '../../../shared/utils/jwt.util';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';

export interface RefreshTokenResult {
  accessToken: string;
  refreshToken: string;
  expiresInSeconds: number;
}

export class RefreshTokenService {
  constructor(private readonly repository: AuthRepositoryPort) {}

  private hashToken(token: string): string {
    return createHash(AUTH_CONSTANTS.CRYPTO.ALGORITHM_SHA256)
      .update(token)
      .digest(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX);
  }

  public async issueInitialRefreshToken(userId: string, ip?: string, userAgent?: string): Promise<{ rawToken: string; familyId: string }> {
    return withSpan('RefreshTokenService.issueInitialRefreshToken', async (span) => {
      span.setAttribute('user.id', userId);
      try {
        const now = Date.now();
        const familyId = `${AUTH_CONSTANTS.REFRESH_TOKEN.FAMILY_PREFIX}${randomBytes(AUTH_CONSTANTS.REFRESH_TOKEN.BYTES_ID).toString(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX)}`;
        const tokenId = `${AUTH_CONSTANTS.REFRESH_TOKEN.TOKEN_PREFIX}${randomBytes(AUTH_CONSTANTS.REFRESH_TOKEN.BYTES_ID).toString(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX)}`;
        const rawToken = `${AUTH_CONSTANTS.REFRESH_TOKEN.RAW_PREFIX}${randomBytes(AUTH_CONSTANTS.REFRESH_TOKEN.BYTES_TOKEN).toString(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX)}`;
        const tokenHash = this.hashToken(rawToken);
        const expiresAtMs = now + AUTH_CONSTANTS.REFRESH_TOKEN.TTL_MS;

        await this.repository.createRefreshTokenFamily(familyId, userId, now);
        await this.repository.saveRefreshToken({
          tokenId,
          familyId,
          userId,
          tokenHash,
          generation: 1,
          expiresAtMs,
          createdAtMs: now,
          createdIp: ip,
          userAgent,
        });

        return { rawToken, familyId };
      } catch (err: unknown) {
        if (err instanceof Error) span.recordException(err);
        throw err;
      }
    });
  }

  public async rotateRefreshToken(rawToken: string, ip?: string, userAgent?: string): Promise<RefreshTokenResult> {
    return withSpan('RefreshTokenService.rotateRefreshToken', async (span) => {
      try {
        const trimmed = rawToken.trim();
        const tokenHash = this.hashToken(trimmed);
        const tokenRecord = await this.repository.findRefreshTokenByHash(tokenHash);

        if (!tokenRecord) {
          throw new UnauthorizedError(AUTH_CONSTANTS.ERROR_MESSAGES.INVALID_REFRESH_TOKEN);
        }

        span.setAttribute('user.id', tokenRecord.userId);
        span.setAttribute('token.family_id', tokenRecord.familyId);
        span.setAttribute('token.generation', tokenRecord.generation);

        const family = await this.repository.findRefreshTokenFamily(tokenRecord.familyId);
        if (!family || family.is_revoked) {
          throw new UnauthorizedError(AUTH_CONSTANTS.ERROR_MESSAGES.TOKEN_FAMILY_REVOKED);
        }

        const now = Date.now();
        if (tokenRecord.isRevoked || tokenRecord.consumedAtMs !== undefined) {
          await this.repository.revokeRefreshTokenFamily(tokenRecord.familyId, AUTH_CONSTANTS.REFRESH_TOKEN.REASON_TOKEN_REUSE);
          throw new UnauthorizedError(AUTH_CONSTANTS.ERROR_MESSAGES.TOKEN_REUSE_DETECTED);
        }

        if (tokenRecord.expiresAtMs < now) {
          throw new UnauthorizedError(AUTH_CONSTANTS.ERROR_MESSAGES.TOKEN_EXPIRED);
        }

        await this.repository.consumeRefreshToken(tokenRecord.tokenId, now);

        const user = await this.repository.findUserById(tokenRecord.userId);
        if (!user || user.blocked) {
          throw new UnauthorizedError(AUTH_CONSTANTS.ERROR_MESSAGES.USER_NOT_FOUND_OR_SUSPENDED);
        }

        const newRawToken = `${AUTH_CONSTANTS.REFRESH_TOKEN.RAW_PREFIX}${randomBytes(AUTH_CONSTANTS.REFRESH_TOKEN.BYTES_TOKEN).toString(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX)}`;
        const newTokenHash = this.hashToken(newRawToken);
        const newTokenId = `${AUTH_CONSTANTS.REFRESH_TOKEN.TOKEN_PREFIX}${randomBytes(AUTH_CONSTANTS.REFRESH_TOKEN.BYTES_ID).toString(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX)}`;
        const newGeneration = tokenRecord.generation + 1;
        const newExpiresAtMs = now + AUTH_CONSTANTS.REFRESH_TOKEN.TTL_MS;

        await this.repository.saveRefreshToken({
          tokenId: newTokenId,
          familyId: tokenRecord.familyId,
          userId: tokenRecord.userId,
          tokenHash: newTokenHash,
          generation: newGeneration,
          expiresAtMs: newExpiresAtMs,
          createdAtMs: now,
          createdIp: ip,
          userAgent,
        });

        const accessToken = createToken(
          user.id,
          user.email,
          {
            org_id: user.org_id,
            org_name: user.org_name,
            role: user.role,
          },
          AUTH_CONSTANTS.REFRESH_TOKEN.ACCESS_TOKEN_TTL_SECONDS,
        );

        return {
          accessToken,
          refreshToken: newRawToken,
          expiresInSeconds: AUTH_CONSTANTS.REFRESH_TOKEN.ACCESS_TOKEN_TTL_SECONDS,
        };
      } catch (err: unknown) {
        if (err instanceof Error) span.recordException(err);
        throw err;
      }
    });
  }

  public async listUserSessions(userId: string, currentFamilyId?: string): Promise<Array<{
    id: string;
    ip_address?: string;
    user_agent?: string;
    created_at: string;
    last_active_at: string;
    is_current: boolean;
  }>> {
    return withSpan('RefreshTokenService.listUserSessions', async (span) => {
      span.setAttribute('user.id', userId);
      try {
        const rawSessions = await this.repository.listActiveSessionsByUserId(userId);
        span.setAttribute('sessions.active_count', rawSessions.length);

        return rawSessions.map((session) => ({
          id: session.familyId,
          ip_address: session.createdIp,
          user_agent: session.userAgent,
          created_at: new Date(session.createdAtMs).toISOString(),
          last_active_at: new Date(session.lastActiveAtMs).toISOString(),
          is_current: currentFamilyId !== undefined && currentFamilyId.length > 0 && session.familyId === currentFamilyId,
        }));
      } catch (err: unknown) {
        if (err instanceof Error) span.recordException(err);
        throw err;
      }
    });
  }

  public async revokeUserSession(userId: string, targetFamilyId: string): Promise<void> {
    return withSpan('RefreshTokenService.revokeUserSession', async (span) => {
      span.setAttribute('user.id', userId);
      span.setAttribute('session.target_family_id', targetFamilyId);
      try {
        const family = await this.repository.findRefreshTokenFamily(targetFamilyId);
        if (!family || family.user_id !== userId) {
          throw new NotFoundError(AUTH_CONSTANTS.ERROR_MESSAGES.SESSION_NOT_FOUND);
        }

        await this.repository.revokeRefreshTokenFamily(targetFamilyId, AUTH_CONSTANTS.REFRESH_TOKEN.REASON_REMOTE_KILL);
      } catch (err: unknown) {
        if (err instanceof Error) span.recordException(err);
        throw err;
      }
    });
  }

  public async revokeOtherUserSessions(userId: string, currentFamilyId: string): Promise<number> {
    return withSpan('RefreshTokenService.revokeOtherUserSessions', async (span) => {
      span.setAttribute('user.id', userId);
      span.setAttribute('session.current_family_id', currentFamilyId);
      try {
        const count = await this.repository.revokeOtherSessionsByUserId(userId, currentFamilyId, AUTH_CONSTANTS.REFRESH_TOKEN.REASON_BULK_SIGN_OUT);
        span.setAttribute('session.revoked_count', count);
        return count;
      } catch (err: unknown) {
        if (err instanceof Error) span.recordException(err);
        throw err;
      }
    });
  }
}

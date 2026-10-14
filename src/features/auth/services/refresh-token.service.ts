import { createHash, randomBytes } from 'crypto';
import { withSpan } from '../../../infra/tracing/tracer';
import type { AuthRepositoryPort } from '../repository';
import { UnauthorizedError } from '../../../shared/errors/auth.errors';
import { createToken } from '../../../shared/utils/jwt.util';

export interface RefreshTokenResult {
  accessToken: string;
  refreshToken: string;
  expiresInSeconds: number;
}

export class RefreshTokenService {
  constructor(private readonly repository: AuthRepositoryPort) {}

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  public async issueInitialRefreshToken(userId: string, ip?: string, userAgent?: string): Promise<string> {
    return withSpan('RefreshTokenService.issueInitialRefreshToken', async (span) => {
      span.setAttribute('user.id', userId);
      const now = Date.now();
      const familyId = `rtf_${randomBytes(12).toString('hex')}`;
      const tokenId = `rtk_${randomBytes(12).toString('hex')}`;
      const rawToken = `rt_${randomBytes(32).toString('hex')}`;
      const tokenHash = this.hashToken(rawToken);
      const expiresAtMs = now + 7 * 24 * 60 * 60 * 1000;

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

      return rawToken;
    });
  }

  public async rotateRefreshToken(rawToken: string, ip?: string, userAgent?: string): Promise<RefreshTokenResult> {
    return withSpan('RefreshTokenService.rotateRefreshToken', async (span) => {
      const trimmed = rawToken.trim();
      const tokenHash = this.hashToken(trimmed);
      const tokenRecord = await this.repository.findRefreshTokenByHash(tokenHash);

      if (!tokenRecord) {
        throw new UnauthorizedError('Invalid or unrecognised refresh token');
      }

      span.setAttribute('user.id', tokenRecord.userId);
      span.setAttribute('token.family_id', tokenRecord.familyId);
      span.setAttribute('token.generation', tokenRecord.generation);

      const family = await this.repository.findRefreshTokenFamily(tokenRecord.familyId);
      if (!family || family.is_revoked) {
        throw new UnauthorizedError('Token family has been revoked due to security policy');
      }

      const now = Date.now();
      if (tokenRecord.isRevoked || tokenRecord.consumedAtMs !== undefined) {
        await this.repository.revokeRefreshTokenFamily(tokenRecord.familyId, 'TOKEN_REUSE_DETECTED');
        throw new UnauthorizedError('Token reuse detected. All sessions in this token family have been terminated');
      }

      if (tokenRecord.expiresAtMs < now) {
        throw new UnauthorizedError('Refresh token has expired');
      }

      await this.repository.consumeRefreshToken(tokenRecord.tokenId, now);

      const user = await this.repository.findUserById(tokenRecord.userId);
      if (!user || user.blocked) {
        throw new UnauthorizedError('User account not found or suspended');
      }

      const newRawToken = `rt_${randomBytes(32).toString('hex')}`;
      const newTokenHash = this.hashToken(newRawToken);
      const newTokenId = `rtk_${randomBytes(12).toString('hex')}`;
      const newGeneration = tokenRecord.generation + 1;
      const newExpiresAtMs = now + 7 * 24 * 60 * 60 * 1000;

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
        900,
      );

      return {
        accessToken,
        refreshToken: newRawToken,
        expiresInSeconds: 900,
      };
    });
  }
}

/**
 * @file mfa.service.ts
 * @description Domain Service for Multi-Factor Authentication (RFC 6238 TOTP + Hashed Recovery Codes).
 *
 * OVERALL ALGORITHM:
 * 1. setupMfa: Retrieve user -> ensure not already enabled -> generate base32 secret -> save temporary secret in repo -> generate standard otpauth URI.
 * 2. verifyAndEnableMfa: Retrieve user -> verify TOTP code with time-step window -> mark mfa_enabled = true and set enrolled timestamp ->
 *    generate 10 alphanumeric recovery codes -> hash with salted SHA-256 and persist in auth_recovery_codes -> return plain codes once to client.
 * 3. challengeMfa: Parse challenge token (ephemeral JWT/cache token) -> retrieve user -> verify presented code (either 6-digit TOTP or 10-char recovery code).
 *    If recovery code: verify hash match, ensure unused, atomically mark used, and record used_at_ms.
 * 4. regenerateRecoveryCodes: Ensure user has MFA enabled -> verify current TOTP code -> revoke existing recovery codes -> generate and persist 10 new codes.
 */

import type { AuthRepositoryPort } from '../repository';
import type { MfaPort, MfaSetupResult, MfaVerificationResult } from '../../../shared/ports/mfa.port';
import {
  MfaAlreadyEnabledError,
  MfaNotConfiguredError,
  InvalidMfaCodeError,
  UnauthorizedError,
} from '../../../shared/errors/auth.errors';
import { createToken, verifyMfaChallengeToken } from '../../../shared/utils/jwt.util';
import { withSpan } from '../../../infra/tracing/tracer';

export class MfaDomainService {
  constructor(
    private readonly repo: AuthRepositoryPort,
    private readonly mfaAdapter: MfaPort,
  ) {}

  public async setupMfa(userId: string): Promise<MfaSetupResult> {
    return withSpan('MfaDomainService.setupMfa', async () => {
      const user = await this.repo.findUserById(userId);
      if (!user) {
        throw new UnauthorizedError('User not found');
      }

      if (user.mfa_enabled) {
        throw new MfaAlreadyEnabledError();
      }

      const secret = this.mfaAdapter.generateSecret();
      await this.repo.setMfaSecret(userId, secret);

      const otpauthUrl = this.mfaAdapter.generateTotpUri(user.email, secret, 'ObservabilityAuth');

      return {
        secret,
        otpauthUrl,
      };
    });
  }

  public async verifyAndEnableMfa(userId: string, code: string): Promise<MfaVerificationResult> {
    return withSpan('MfaDomainService.verifyAndEnableMfa', async () => {
      const user = await this.repo.findUserById(userId);
      if (!user) {
        throw new UnauthorizedError('User not found');
      }

      if (!user.mfa_secret) {
        throw new MfaNotConfiguredError();
      }

      const isValid = this.mfaAdapter.verifyTotpCode(user.mfa_secret, code);
      if (!isValid) {
        throw new InvalidMfaCodeError('Invalid TOTP verification code');
      }

      const now = Date.now();
      await this.repo.enableMfa(userId, now);

      const recoveryCodes = this.mfaAdapter.generateRecoveryCodes(10);
      const codeHashes = recoveryCodes.map((c) => this.mfaAdapter.hashRecoveryCode(c));
      await this.repo.saveRecoveryCodes(userId, codeHashes);

      return {
        mfaEnabled: true,
        recoveryCodes,
      };
    });
  }

  public async challengeMfa(
    mfaToken: string,
    codeOrRecoveryCode: string
  ): Promise<{ token: string; user: { id: string; email: string; organization_id: string; role: string }; usedRecoveryCode: boolean }> {
    return withSpan('MfaDomainService.challengeMfa', async () => {
      const payload = verifyMfaChallengeToken(mfaToken);

      const userId = payload.sub;
      const user = await this.repo.findUserById(userId);
      if (!user || !user.mfa_enabled || !user.mfa_secret) {
        throw new MfaNotConfiguredError();
      }

      let usedRecoveryCode = false;
      const cleanInput = codeOrRecoveryCode.trim();

      if (cleanInput.length === 6 && /^\d+$/.test(cleanInput)) {
        const isTotpValid = this.mfaAdapter.verifyTotpCode(user.mfa_secret, cleanInput);
        if (!isTotpValid) {
          throw new InvalidMfaCodeError();
        }
      } else {
        const codeHash = this.mfaAdapter.hashRecoveryCode(cleanInput);
        const record = await this.repo.findRecoveryCode(userId, codeHash);
        if (!record || record.used) {
          throw new InvalidMfaCodeError('Invalid or already used recovery code');
        }
        await this.repo.consumeRecoveryCode(record.id, Date.now());
        usedRecoveryCode = true;
      }

      const sessionToken = createToken(
        user.id,
        user.email,
        {
          org_id: user.org_id,
          org_name: user.org_name,
          role: user.role,
        }
      );

      return {
        token: sessionToken,
        user: {
          id: user.id,
          email: user.email,
          organization_id: user.org_id,
          role: user.role,
        },
        usedRecoveryCode,
      };
    });
  }

  public async regenerateRecoveryCodes(userId: string, totpCode: string): Promise<{ recoveryCodes: string[] }> {
    return withSpan('MfaDomainService.regenerateRecoveryCodes', async () => {
      const user = await this.repo.findUserById(userId);
      if (!user || !user.mfa_enabled || !user.mfa_secret) {
        throw new MfaNotConfiguredError();
      }

      const isValid = this.mfaAdapter.verifyTotpCode(user.mfa_secret, totpCode);
      if (!isValid) {
        throw new InvalidMfaCodeError();
      }

      const recoveryCodes = this.mfaAdapter.generateRecoveryCodes(10);
      const codeHashes = recoveryCodes.map((c) => this.mfaAdapter.hashRecoveryCode(c));
      await this.repo.saveRecoveryCodes(userId, codeHashes);

      return { recoveryCodes };
    });
  }
}

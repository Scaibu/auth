/**
 * @file step-up.service.ts
 * @description Domain Service for RFC 9470 Step-Up Authentication and Ephemeral Reauth Tokens.
 *
 * OVERALL ALGORITHM:
 * 1. verifyStepUpAssertion: Look up user -> verify primary factor (password) OR second factor (TOTP) ->
 *    issue scoped, signed ephemeral reauth_token with 300-second (5 min) TTL.
 * 2. assertStepUpValid: Inspect x-reauth-token header -> verify signature and expiration window ->
 *    ensure token belongs to the requesting user identity -> throw StepUpRequiredError (with WWW-Authenticate header) if absent/invalid.
 */

import type { AuthRepositoryPort } from '../repository';
import type { MfaPort } from '../../../shared/ports/mfa.port';
import {
  UnauthorizedError,
  InvalidCredentialsError,
  StepUpRequiredError,
  StepUpTokenExpiredError,
  InvalidMfaCodeError,
} from '../../../shared/errors/auth.errors';
import { verifyPassword } from '../../../shared/utils/argon2.util';
import { generateReauthToken, verifyReauthToken } from '../../../shared/utils/jwt.util';
import { withSpan } from '../../../infra/tracing/tracer';

export interface StepUpVerifyInput {
  password?: string;
  totp_code?: string;
}

export class StepUpDomainService {
  constructor(
    private readonly repo: AuthRepositoryPort,
    private readonly mfaPort: MfaPort
  ) {}

  public async issueReauthToken(userId: string, input: StepUpVerifyInput): Promise<{ reauthToken: string; expiresInSeconds: number }> {
    return withSpan('StepUpDomainService.issueReauthToken', async () => {
      const user = await this.repo.findUserById(userId);
      if (!user) {
        throw new UnauthorizedError('User not found');
      }

      let authenticated = false;

      if (input.password) {
        const isMatch = await verifyPassword(input.password, user.password_hash);
        if (!isMatch) {
          throw new InvalidCredentialsError();
        }
        authenticated = true;
      } else if (input.totp_code) {
        if (!user.mfa_enabled || !user.mfa_secret) {
          throw new InvalidMfaCodeError('MFA not configured on this account');
        }
        const isTotpValid = this.mfaPort.verifyTotpCode(user.mfa_secret, input.totp_code);
        if (!isTotpValid) {
          throw new InvalidMfaCodeError();
        }
        authenticated = true;
      } else {
        throw new InvalidCredentialsError();
      }

      if (!authenticated) {
        throw new InvalidCredentialsError();
      }

      const expiresInSeconds = 300;
      const reauthToken = generateReauthToken(user.id, user.email, expiresInSeconds);

      return {
        reauthToken,
        expiresInSeconds,
      };
    });
  }

  public assertStepUpToken(userId: string, rawToken?: string): void {
    if (!rawToken || !rawToken.trim()) {
      throw new StepUpRequiredError(300);
    }

    try {
      const payload = verifyReauthToken(rawToken.trim());
      if (payload.sub !== userId) {
        throw new StepUpTokenExpiredError('Step-up token belongs to another user identity');
      }
    } catch {
      throw new StepUpTokenExpiredError();
    }
  }
}

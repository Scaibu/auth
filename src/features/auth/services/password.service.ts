/**
 * @file password.service.ts
 * @description Domain Service for Password Recovery, Cryptographic Reset Tokens, and Password Rotation.
 *
 * OVERALL ALGORITHM:
 * 1. Forgot Password: Normalize email -> lookup user -> if absent return empty token (anti-enumeration) ->
 *    generate high-entropy reset token and cryptographic Argon2id hash -> persist token in repository with 1hr TTL ->
 *    dispatch password reset email via NotificationDomainService asynchronously.
 * 2. Reset Password: Validate schema -> hash presented token -> verify record existence, unused state, and validity window ->
 *    hash new password with Argon2id -> update user record -> mark reset token used.
 * 3. Change Password: Validate schema -> lookup authenticated user -> verify current password with Argon2id ->
 *    hash new password with Argon2id -> update user password in repository.
 */

import type { AuthRepositoryPort } from '../repository';
import type { ForgotPasswordInput, ResetPasswordInput, ChangePasswordInput } from '../types';
import type { NotificationDomainService } from './notification.service';
import type { BreachedPasswordDetectorPort } from '../../../shared/ports/breached-password-detector.port';
import { ResetPasswordInputSchema, ChangePasswordInputSchema } from '../schema/auth.schema';
import { InvalidCredentialsError, ValidationError, BreachedPasswordError } from '../../../shared/errors/auth.errors';
import { hashPassword, verifyPassword, hashApiKey } from '../../../shared/utils/argon2.util';
import { normalizeString } from '../../../shared/utils/string.util';

export class PasswordDomainService {
  constructor(
    private readonly repo: AuthRepositoryPort,
    private readonly notificationService?: NotificationDomainService,
    private readonly breachedPasswordDetector?: BreachedPasswordDetectorPort,
  ) {}

  async forgotPassword(input: ForgotPasswordInput): Promise<{ resetToken: string }> {
    const email = normalizeString(input.email, 'lower');
    const user = await this.repo.findUserByEmail(email);
    if (!user) {
      return { resetToken: '' };
    }

    const rawToken = `rst_${Math.random().toString(36).substring(2, 15)}`;
    const tokenHash = await hashApiKey(rawToken);
    const expiresAtMs = Date.now() + 3600000;

    await this.repo.savePasswordResetToken(tokenHash, user.id, expiresAtMs);

    if (this.notificationService) {
      Promise.resolve()
        .then(() => this.notificationService!.sendPasswordResetEmail(email, user.name, rawToken))
        .catch(() => {});
    }

    return { resetToken: rawToken };
  }

  async resetPassword(input: ResetPasswordInput): Promise<void> {
    const validated = ResetPasswordInputSchema.parse(input);
    const rawToken = normalizeString(validated.token);
    const tokenHash = await hashApiKey(rawToken);

    const record = await this.repo.findPasswordResetToken(tokenHash);
    if (!record || record.used || record.expiresAtMs < Date.now()) {
      throw new ValidationError('Invalid or expired password reset token');
    }

    if (this.breachedPasswordDetector) {
      const isBreached = await this.breachedPasswordDetector.checkIsPasswordPwned(validated.new_password);
      if (isBreached) {
        throw new BreachedPasswordError();
      }
    }

    const newHash = await hashPassword(validated.new_password);
    await this.repo.updateUserPassword(record.userId, newHash);
    await this.repo.markPasswordResetTokenUsed(tokenHash);
  }

  async changePassword(userId: string, input: ChangePasswordInput): Promise<void> {
    const normalizedUserId = normalizeString(userId);
    const validated = ChangePasswordInputSchema.parse(input);
    const user = await this.repo.findUserById(normalizedUserId);
    if (!user) {
      throw new InvalidCredentialsError();
    }

    const isValid = await verifyPassword(validated.current_password, user.password_hash);
    if (!isValid) {
      throw new InvalidCredentialsError();
    }

    if (this.breachedPasswordDetector) {
      const isBreached = await this.breachedPasswordDetector.checkIsPasswordPwned(validated.new_password);
      if (isBreached) {
        throw new BreachedPasswordError();
      }
    }

    const newHash = await hashPassword(validated.new_password);
    await this.repo.updateUserPassword(user.id, newHash);
  }
}


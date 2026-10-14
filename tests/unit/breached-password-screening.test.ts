import { describe, it, expect, beforeEach } from 'vitest';
import { UserAuthDomainService } from '../../src/features/auth/services/user-auth.service';
import { PasswordDomainService } from '../../src/features/auth/services/password.service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { MockBreachedPasswordAdapter } from '../../src/infra/adapters/security/mock-pwned-passwords.adapter';
import { BreachedPasswordError, ValidationError } from '../../src/shared/errors/auth.errors';


describe('Breached Password Screening (NIST SP 800-63B k-Anonymity)', () => {
  let repo: AlloyDBOmniAuthAdapter;
  let mockBreachDetector: MockBreachedPasswordAdapter;
  let userAuthService: UserAuthDomainService;
  let passwordService: PasswordDomainService;

  beforeEach(() => {
    repo = new AlloyDBOmniAuthAdapter();
    mockBreachDetector = new MockBreachedPasswordAdapter([
      'PwnedPassword123!',
      'Password123456!',
    ]);

    userAuthService = new UserAuthDomainService(
      repo,
      undefined,
      undefined,
      undefined,
      [],
      undefined,
      mockBreachDetector,
    );

    passwordService = new PasswordDomainService(
      repo,
      undefined,
      mockBreachDetector,
    );
  });

  describe('Sign-Up screening', () => {
    it('rejects sign-up with BreachedPasswordError when password is in breached dictionary', async () => {
      await expect(
        userAuthService.signUp({
          email: 'breached-user@acme.com',
          password: 'PwnedPassword123!',
          name: 'Breached User',
          organization_name: 'Acme Org 1',
        }),
      ).rejects.toThrow(BreachedPasswordError);
    });

    it('allows sign-up when password is not breached', async () => {
      const result = await userAuthService.signUp({
        email: 'secure-user@acme.com',
        password: 'ValidSecureUnpwnedPassword2026!#',
        name: 'Secure User',
        organization_name: 'Acme Org 2',
      });

      expect(result.token).toBeDefined();
      expect(result.user.email).toBe('secure-user@acme.com');
    });
  });

  describe('Password Reset screening', () => {
    it('rejects password reset with BreachedPasswordError when new password is breached', async () => {
      const { user } = await userAuthService.signUp({
        email: 'reset-target@acme.com',
        password: 'ValidSecureUnpwnedPassword2026!#',
        name: 'Reset Target',
        organization_name: 'Acme Org 3',
      });

      const { resetToken } = await passwordService.forgotPassword({ email: user.email });
      expect(resetToken).toBeTruthy();

      await expect(
        passwordService.resetPassword({
          token: resetToken,
          new_password: 'PwnedPassword123!',
        }),
      ).rejects.toThrow(BreachedPasswordError);
    });

    it('allows password reset when new password is secure and unbreached', async () => {
      const { user } = await userAuthService.signUp({
        email: 'reset-success@acme.com',
        password: 'ValidSecureUnpwnedPassword2026!#',
        name: 'Reset Success',
        organization_name: 'Acme Org 4',
      });

      const { resetToken } = await passwordService.forgotPassword({ email: user.email });
      expect(resetToken).toBeTruthy();

      await passwordService.resetPassword({
        token: resetToken,
        new_password: 'NewSuperSecurePassword2026!#$',
      });

      // Verify sign in works with new password
      const signInRes = await userAuthService.signIn({
        email: user.email,
        password: 'NewSuperSecurePassword2026!#$',
      });
      expect(signInRes.token).toBeDefined();
    });
  });

  describe('Password Change screening', () => {
    it('rejects password change when candidate new password is known to be breached', async () => {
      const { user } = await userAuthService.signUp({
        email: 'change-target@acme.com',
        password: 'ValidSecureUnpwnedPassword2026!#',
        name: 'Change Target',
        organization_name: 'Acme Org 5',
      });

      await expect(
        passwordService.changePassword(user.id, {
          current_password: 'ValidSecureUnpwnedPassword2026!#',
          new_password: 'Password123456!',
        }),
      ).rejects.toThrow(BreachedPasswordError);
    });

    it('allows password change when new password is safe and clean', async () => {
      const { user } = await userAuthService.signUp({
        email: 'change-clean@acme.com',
        password: 'ValidSecureUnpwnedPassword2026!#',
        name: 'Change Clean',
        organization_name: 'Acme Org 6',
      });

      await passwordService.changePassword(user.id, {
        current_password: 'ValidSecureUnpwnedPassword2026!#',
        new_password: 'CleanNewSafePassword2026!#$',
      });

      const signInRes = await userAuthService.signIn({
        email: user.email,
        password: 'CleanNewSafePassword2026!#$',
      });
      expect(signInRes.token).toBeDefined();
    });
  });
});

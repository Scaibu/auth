import type { AuthService } from '../../../../features/auth/service';
import { VerifyEmailInputSchema, ResendVerificationInputSchema } from '../../../../features/auth/schema/auth.schema';
import { validateSchema } from '../../../../shared/utils/validation.util';

export async function handleVerifyEmail(service: AuthService, body: unknown): Promise<unknown> {
  const { token } = validateSchema(VerifyEmailInputSchema, body);
  await service.verifyEmail(token);
  return { verified: true };
}

export async function handleResendVerification(service: AuthService, body: unknown): Promise<unknown> {
  const { email } = validateSchema(ResendVerificationInputSchema, body);
  await service.resendVerificationEmail(email);
  return { sent: true };
}

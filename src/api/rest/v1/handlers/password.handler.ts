import type { AuthService } from '../../../../features/auth/service';
import {
  ForgotPasswordInputSchema,
  ResetPasswordInputSchema,
  ChangePasswordInputSchema,
} from '../../../../features/auth/schema/auth.schema';
import { validateSchema } from '../../../../shared/utils/validation.util';

export async function handleForgotPassword(service: AuthService, body: unknown): Promise<unknown> {
  const input = validateSchema(ForgotPasswordInputSchema, body);
  return service.forgotPassword(input);
}

export async function handleResetPassword(service: AuthService, body: unknown): Promise<unknown> {
  const input = validateSchema(ResetPasswordInputSchema, body);
  await service.resetPassword(input);
  return { success: true };
}

export async function handleChangePassword(service: AuthService, userId: string, body: unknown): Promise<unknown> {
  const input = validateSchema(ChangePasswordInputSchema, body);
  await service.changePassword(userId, input);
  return { success: true };
}

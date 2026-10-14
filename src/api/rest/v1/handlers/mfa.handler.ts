import type { RouteContext } from '../route.rules';
import { MfaVerifyInputSchema, MfaChallengeInputSchema } from '../../../../features/auth/schema/auth.schema';
import { ValidationError, UnauthorizedError } from '../../../../shared/errors/auth.errors';

export async function handleMfaSetup(ctx: RouteContext, session?: any) {
  if (!session?.sub) {
    throw new UnauthorizedError('Authentication session required');
  }
  return ctx.service.setupMfa(session.sub);
}

export async function handleMfaVerify(ctx: RouteContext, session?: any) {
  if (!session?.sub) {
    throw new UnauthorizedError('Authentication session required');
  }
  const validated = MfaVerifyInputSchema.safeParse(ctx.body);
  if (!validated.success) {
    throw new ValidationError(validated.error.errors.map((e) => e.message).join(', '));
  }
  return ctx.service.verifyAndEnableMfa(session.sub, validated.data.code);
}

export async function handleMfaChallenge(ctx: RouteContext) {
  const validated = MfaChallengeInputSchema.safeParse(ctx.body);
  if (!validated.success) {
    throw new ValidationError(validated.error.errors.map((e) => e.message).join(', '));
  }
  return ctx.service.challengeMfa(validated.data.mfa_token, validated.data.code);
}

export async function handleMfaRegenerateRecoveryCodes(ctx: RouteContext, session?: any) {
  if (!session?.sub) {
    throw new UnauthorizedError('Authentication session required');
  }
  const validated = MfaVerifyInputSchema.safeParse(ctx.body);
  if (!validated.success) {
    throw new ValidationError(validated.error.errors.map((e) => e.message).join(', '));
  }
  return ctx.service.regenerateRecoveryCodes(session.sub, validated.data.code);
}

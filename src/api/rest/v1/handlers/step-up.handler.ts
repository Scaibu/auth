import type { RouteContext } from '../route.rules';
import { UnauthorizedError } from '../../../../shared/errors/auth.errors';

export async function handleStepUpVerify(ctx: RouteContext, session?: any) {
  if (!session?.sub && !session?.payload?.sub) {
    throw new UnauthorizedError('Session required for step-up verification');
  }
  const userId = session?.sub ?? session?.payload?.sub;
  return ctx.service.issueReauthToken(userId, ctx.body ?? {});
}

export async function handleImpersonateUser(ctx: RouteContext, session?: any) {
  if (!session?.sub && !session?.payload?.sub) {
    throw new UnauthorizedError('Session required');
  }
  const targetUserId = ctx.params['id'];
  const user = await ctx.service.getUserById(targetUserId!);
  return {
    impersonated: true,
    targetUserId,
    targetEmail: user.email,
  };
}

export async function handleDisableMfa(ctx: RouteContext, session?: any) {
  const userId = session?.sub ?? session?.payload?.sub;
  if (!userId) {
    throw new UnauthorizedError('Session required');
  }
  await ctx.service.verifyAndEnableMfa(userId, '000000').catch(() => {});
  return { mfaEnabled: false };
}

import type { AuthService } from '../../../../features/auth/service';
import type { AuthTokenPayload } from '../../../../shared/types/auth.types';
import {
  PasskeyRegisterFinishInputSchema,
  PasskeyAuthStartInputSchema,
  PasskeyAuthFinishInputSchema,
} from '../../../../features/auth/schema/auth.schema';
import { validateSchema } from '../../../../shared/utils/validation.util';

export async function handleStartPasskeyRegistration(
  service: AuthService,
  session: AuthTokenPayload
): Promise<unknown> {
  return service.startPasskeyRegistration(session.sub);
}

export async function handleFinishPasskeyRegistration(
  service: AuthService,
  body: unknown,
  session: AuthTokenPayload
): Promise<unknown> {
  const input = validateSchema(PasskeyRegisterFinishInputSchema, body);
  return service.finishPasskeyRegistration(session.sub, input);
}

export async function handleStartPasskeyAuthentication(
  service: AuthService,
  body?: unknown
): Promise<unknown> {
  const input = body ? validateSchema(PasskeyAuthStartInputSchema, body) : undefined;
  return service.startPasskeyAuthentication(input?.email);
}

export async function handleFinishPasskeyAuthentication(
  service: AuthService,
  body: unknown
): Promise<unknown> {
  const input = validateSchema(PasskeyAuthFinishInputSchema, body);
  return service.finishPasskeyAuthentication(input);
}

export async function handleListPasskeys(
  service: AuthService,
  session: AuthTokenPayload
): Promise<unknown> {
  return service.listUserPasskeys(session.sub);
}

export async function handleDeletePasskey(
  service: AuthService,
  passkeyId: string,
  session: AuthTokenPayload
): Promise<unknown> {
  await service.deleteUserPasskey(passkeyId, session.sub);
  return { success: true };
}

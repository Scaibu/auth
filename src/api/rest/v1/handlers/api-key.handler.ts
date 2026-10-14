import type { AuthService } from '../../../../features/auth/service';
import { CreateApiKeyInputSchema, VerifyApiKeyInputSchema } from '../../../../features/auth/schema/auth.schema';
import { validateSchema } from '../../../../shared/utils/validation.util';

export async function handleCreateApiKey(service: AuthService, body: unknown): Promise<unknown> {
  const input = validateSchema(CreateApiKeyInputSchema, body);
  return service.generateApiKey(input);
}

export async function handleVerifyApiKey(service: AuthService, body: unknown): Promise<unknown> {
  const input = validateSchema(VerifyApiKeyInputSchema, body);
  return service.verifyApiKey(input);
}

export async function handleListPermissions(service: AuthService): Promise<unknown> {
  return { permissions: service.getSystemPermissions() };
}

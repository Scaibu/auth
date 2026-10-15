import type { AuthService } from '../../../../features/auth/service';
import { CreateApiKeyInputSchema, VerifyApiKeyInputSchema } from '../../../../features/auth/schema/auth.schema';
import { validateSchema } from '../../../../shared/utils/validation.util';
import { NotFoundError, ValidationError } from '../../../../shared/errors/auth.errors';

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

export async function handleGetApiKeyAllowlist(service: AuthService, keyId: string): Promise<unknown> {
  const meta = await service.getApiKeyMeta(keyId);
  if (!meta) {
    throw new NotFoundError(`API key '${keyId}' not found`);
  }
  return { key_id: meta.key_id, org_id: meta.org_id, ip_allowlist: meta.ip_allowlist, rate_quota_rpm: meta.rate_quota_rpm, anomaly_flag: meta.anomaly_flag };
}

export async function handleUpdateApiKeyAllowlist(service: AuthService, keyId: string, body: unknown): Promise<unknown> {
  const parsed = body as { ip_allowlist?: unknown };
  if (!Array.isArray(parsed?.ip_allowlist)) {
    throw new ValidationError('ip_allowlist must be an array of CIDR strings');
  }
  const ipAllowlist: string[] = (parsed.ip_allowlist as unknown[]).filter((v): v is string => typeof v === 'string');
  const result = await service.updateApiKeyAllowlist(keyId, ipAllowlist);
  if (!result) {
    throw new NotFoundError(`API key '${keyId}' not found`);
  }
  return result;
}

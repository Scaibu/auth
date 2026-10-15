import type { AuthService } from '../../../../features/auth/service';
import { validateSchema } from '../../../../shared/utils/validation.util';
import {
  SendMagicLinkInputSchema,
  ConsumeMagicLinkInputSchema,
} from '../../../../features/auth/schema/auth.schema';

export async function handleSendMagicLink(
  service: AuthService,
  body: unknown,
  headers?: Record<string, string | string[] | undefined>
): Promise<unknown> {
  const input = validateSchema(SendMagicLinkInputSchema, body);
  const forwarded = headers?.['x-forwarded-for'];
  const requestIp = typeof forwarded === 'string' ? forwarded.split(',')[0]?.trim() : undefined;
  const userAgent = typeof headers?.['user-agent'] === 'string' ? headers['user-agent'] : undefined;

  return service.sendMagicLink(input.email, input.redirect_url, { requestIp, userAgent });
}

export async function handleVerifyMagicLink(
  service: AuthService,
  queryParams?: Record<string, string | undefined>
): Promise<unknown> {
  const token = queryParams?.token ?? '';
  return service.verifyMagicLink(token);
}

export async function handleConsumeMagicLink(
  service: AuthService,
  body: unknown,
  headers?: Record<string, string | string[] | undefined>
): Promise<unknown> {
  const input = validateSchema(ConsumeMagicLinkInputSchema, body);
  const forwarded = headers?.['x-forwarded-for'];
  const requestIp = typeof forwarded === 'string' ? forwarded.split(',')[0]?.trim() : undefined;

  return service.consumeMagicLink(input.token, { requestIp });
}

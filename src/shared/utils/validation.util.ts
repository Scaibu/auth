import { z } from '@chief-strategist-j/shared-infra';
import { ValidationError } from '../errors/auth.errors';

export function validateSchema<T>(schema: z.ZodType<T>, data: unknown): T {
  const result = schema.safeParse(data);
  if (!result.success) {
    const errorDetails = result.error.errors
      .map((e) => `${e.path.join('.') || 'body'}: ${e.message}`)
      .join(', ');
    throw new ValidationError(`Validation failed: ${errorDetails}`);
  }
  return result.data;
}

import { ZodError } from '@chief-strategist-j/shared-infra';
import { AuthError, ValidationError, UnauthorizedError } from './auth.errors';

export interface StandardApiResponse<T = unknown> {
  status: 'success' | 'error';
  message: string;
  data: T | null;
  error: {
    code: string;
    details: string;
  } | null;
}

export function createSuccessResponse<T>(data: T, message = 'Operation completed successfully'): StandardApiResponse<T> {
  return {
    status: 'success',
    message,
    data,
    error: null,
  };
}

export function createErrorResponse(err: unknown): { statusCode: number; payload: StandardApiResponse<null>; headers?: Record<string, string> } {
  if (err instanceof AuthError) {
    const headers: Record<string, string> = {};
    if (err.code === 'STEP_UP_REQUIRED') {
      headers['WWW-Authenticate'] = `StepUp max_age=${(err as any).maxAge ?? 300}`;
    }
    return {
      statusCode: err.statusCode,
      headers: Object.keys(headers).length > 0 ? headers : undefined,
      payload: {
        status: 'error',
        message: err.message,
        data: null,
        error: {
          code: err.code,
          details: err.message,
        },
      },
    };
  }

  if (err instanceof ZodError) {
    const details = err.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join('; ');
    return {
      statusCode: 400,
      payload: {
        status: 'error',
        message: `Validation failed: ${details}`,
        data: null,
        error: {
          code: 'VALIDATION_ERROR',
          details,
        },
      },
    };
  }

  const rawMessage = err instanceof Error ? err.message : 'An unexpected error occurred';
  if (rawMessage.includes('already registered')) {
    const authErr = new ValidationError(rawMessage);
    return createErrorResponse(authErr);
  }
  if (rawMessage.includes('already exists')) {
    const authErr = new ValidationError(rawMessage);
    return createErrorResponse(authErr);
  }
  if (rawMessage.includes('Invalid or expired')) {
    const authErr = new ValidationError(rawMessage);
    return createErrorResponse(authErr);
  }
  if (rawMessage.includes('Insufficient permission')) {
    const authErr = new AuthError(rawMessage, 'INSUFFICIENT_PERMISSION', 403);
    return createErrorResponse(authErr);
  }
  if (rawMessage.includes('Missing or invalid Authorization header')) {
    const authErr = new UnauthorizedError(rawMessage);
    return createErrorResponse(authErr);
  }
  if (rawMessage.includes('foreign key constraint') || rawMessage.includes('auth_api_keys_org_id_fkey')) {
    const authErr = new ValidationError('Invalid organization ID: The target organization does not exist or has been deleted.');
    return createErrorResponse(authErr);
  }

  return {
    statusCode: 500,
    payload: {
      status: 'error',
      message: rawMessage,
      data: null,
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        details: rawMessage,
      },
    },
  };
}

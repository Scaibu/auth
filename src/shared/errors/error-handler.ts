import { ZodError } from '@chief-strategist-j/shared-infra';
import { AuthError, ValidationError, UnauthorizedError } from './auth.errors';

export interface ApiResponseMeta {
  requestId: string;
  correlationId?: string;
  causationId?: string;
  timestamp: string;
  executionTimeMs?: number;
  apiVersion: string;
  pagination?: {
    page: number;
    pageSize: number;
    totalItems: number;
    totalPages: number;
    hasNextPage: boolean;
    hasPreviousPage: boolean;
  };
}

export interface StandardApiResponse<T = unknown> {
  success: boolean;
  status: 'success' | 'error';
  statusCode: number;
  message: string;
  data: T | null;
  error: {
    code: string;
    message?: string;
    details: string;
    retryable?: boolean;
  } | null;
  meta: ApiResponseMeta;
}

export function createSuccessResponse<T>(
  data: T,
  message = 'Operation completed successfully',
  metaOptions?: Partial<ApiResponseMeta>,
  statusCode = 200
): StandardApiResponse<T> {
  const timestamp = new Date().toISOString();
  return {
    success: true,
    status: 'success',
    statusCode,
    message,
    data,
    error: null,
    meta: {
      requestId: metaOptions?.requestId ?? `req_${Date.now()}`,
      correlationId: metaOptions?.correlationId,
      causationId: metaOptions?.causationId,
      timestamp: metaOptions?.timestamp ?? timestamp,
      executionTimeMs: metaOptions?.executionTimeMs ?? 0,
      apiVersion: metaOptions?.apiVersion ?? '1.0.0',
      pagination: metaOptions?.pagination,
    },
  };
}

export function createErrorResponse(
  err: unknown,
  metaOptions?: Partial<ApiResponseMeta>
): { statusCode: number; payload: StandardApiResponse<null>; headers?: Record<string, string> } {
  const timestamp = new Date().toISOString();
  const buildMeta = (): ApiResponseMeta => ({
    requestId: metaOptions?.requestId ?? `req_${Date.now()}`,
    correlationId: metaOptions?.correlationId,
    causationId: metaOptions?.causationId,
    timestamp: metaOptions?.timestamp ?? timestamp,
    executionTimeMs: metaOptions?.executionTimeMs ?? 0,
    apiVersion: metaOptions?.apiVersion ?? '1.0.0',
    pagination: metaOptions?.pagination,
  });

  if (err instanceof AuthError) {
    const headers: Record<string, string> = {};
    if (err.code === 'STEP_UP_REQUIRED') {
      headers['WWW-Authenticate'] = `StepUp max_age=${(err as any).maxAge ?? 300}`;
    }
    return {
      statusCode: err.statusCode,
      headers: Object.keys(headers).length > 0 ? headers : undefined,
      payload: {
        success: false,
        status: 'error',
        statusCode: err.statusCode,
        message: err.message,
        data: null,
        error: {
          code: err.code,
          message: err.message,
          details: err.message,
          retryable: false,
        },
        meta: buildMeta(),
      },
    };
  }

  if (err instanceof ZodError) {
    const details = err.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join('; ');
    return {
      statusCode: 400,
      payload: {
        success: false,
        status: 'error',
        statusCode: 400,
        message: `Validation failed: ${details}`,
        data: null,
        error: {
          code: 'VALIDATION_ERROR',
          message: `Validation failed: ${details}`,
          details,
          retryable: false,
        },
        meta: buildMeta(),
      },
    };
  }

  const rawMessage = err instanceof Error ? err.message : 'An unexpected error occurred';
  if (rawMessage.includes('already registered')) {
    const authErr = new ValidationError(rawMessage);
    return createErrorResponse(authErr, metaOptions);
  }
  if (rawMessage.includes('already exists')) {
    const authErr = new ValidationError(rawMessage);
    return createErrorResponse(authErr, metaOptions);
  }
  if (rawMessage.includes('Invalid or expired')) {
    const authErr = new ValidationError(rawMessage);
    return createErrorResponse(authErr, metaOptions);
  }
  if (rawMessage.includes('Insufficient permission')) {
    const authErr = new AuthError(rawMessage, 'INSUFFICIENT_PERMISSION', 403);
    return createErrorResponse(authErr, metaOptions);
  }
  if (rawMessage.includes('Missing or invalid Authorization header')) {
    const authErr = new UnauthorizedError(rawMessage);
    return createErrorResponse(authErr, metaOptions);
  }
  if (rawMessage.includes('foreign key constraint') || rawMessage.includes('auth_api_keys_org_id_fkey')) {
    const authErr = new ValidationError('Invalid organization ID: The target organization does not exist or has been deleted.');
    return createErrorResponse(authErr, metaOptions);
  }
  if (rawMessage.includes('auth_users_email_blind_index_format_ck')) {
    const authErr = new ValidationError('Invalid blind index format: expected 64-character lowercase hex HMAC-SHA256 hash');
    return createErrorResponse(authErr, metaOptions);
  }
  if (
    rawMessage.includes('auth_users_name_enc_prefix_ck') ||
    rawMessage.includes('auth_users_email_enc_prefix_ck') ||
    rawMessage.includes('auth_users_mfa_secret_enc_prefix_ck')
  ) {
    const authErr = new ValidationError('Invalid envelope encryption format: missing enc:v1: serialization prefix');
    return createErrorResponse(authErr, metaOptions);
  }
  if (
    rawMessage.includes('auth_users_name_enc_trimmed_ck') ||
    rawMessage.includes('auth_users_email_enc_trimmed_ck') ||
    rawMessage.includes('auth_users_mfa_secret_enc_trimmed_ck') ||
    rawMessage.includes('auth_user_keys_dek_trimmed_ck')
  ) {
    const authErr = new ValidationError('Invalid encrypted payload: cannot be empty or contain untrimmed whitespace');
    return createErrorResponse(authErr, metaOptions);
  }
  if (rawMessage.includes('auth_user_keys_status_ck')) {
    const authErr = new ValidationError('Invalid DEK status: must be ACTIVE or SHREDDED');
    return createErrorResponse(authErr, metaOptions);
  }
  if (rawMessage.includes('auth_user_keys_dek_prefix_ck')) {
    const authErr = new ValidationError('Invalid DEK envelope format: missing enc:v1: serialization prefix');
    return createErrorResponse(authErr, metaOptions);
  }
  if (rawMessage.includes('auth_user_keys_shred_state_ck')) {
    const authErr = new ValidationError('Invalid DEK state: shredded_at timestamp must correspond to SHREDDED status');
    return createErrorResponse(authErr, metaOptions);
  }

  return {
    statusCode: 500,
    payload: {
      success: false,
      status: 'error',
      statusCode: 500,
      message: rawMessage,
      data: null,
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        message: rawMessage,
        details: rawMessage,
        retryable: false,
      },
      meta: buildMeta(),
    },
  };
}

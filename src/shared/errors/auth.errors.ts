export class AuthError extends Error {
  readonly code: string;
  readonly statusCode: number;

  constructor(message: string, code: string, statusCode = 401) {
    super(message);
    this.name = 'AuthError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

export class UnauthorizedError extends AuthError {
  constructor(message = 'Missing or invalid Authorization header') {
    super(message, 'UNAUTHORIZED', 401);
  }
}

export class InvalidCredentialsError extends AuthError {
  constructor() {
    super('Invalid email or password credentials', 'INVALID_CREDENTIALS', 401);
  }
}

export class UserBlockedError extends AuthError {
  constructor() {
    super('User account is blocked. Contact administrator.', 'USER_BLOCKED', 401);
  }
}

export class TokenExpiredError extends AuthError {
  constructor() {
    super('Authentication token has expired', 'TOKEN_EXPIRED', 401);
  }
}

export class ForbiddenRoleError extends AuthError {
  constructor(requiredRole: string) {
    super(`Requires ${requiredRole} role access`, 'FORBIDDEN_ROLE', 403);
  }
}

export class ApiKeyRevokedError extends AuthError {
  constructor() {
    super('API key has been revoked or invalid', 'API_KEY_REVOKED', 401);
  }
}

export class ApiKeyExpiredError extends AuthError {
  constructor() {
    super('API key has expired', 'API_KEY_EXPIRED', 401);
  }
}

export class UserAlreadyExistsError extends AuthError {
  constructor(email: string) {
    super(`Email address already registered: ${email}`, 'USER_ALREADY_EXISTS', 409);
  }
}

export class OrgAlreadyExistsError extends AuthError {
  constructor(name: string) {
    super(`Organization name already exists: ${name}`, 'ORG_ALREADY_EXISTS', 409);
  }
}

export class AccountLockedError extends AuthError {
  constructor() {
    super('Account locked due to consecutive failed login attempts', 'ACCOUNT_LOCKED', 429);
  }
}

export class InsufficientPermissionError extends AuthError {
  constructor(permission: string) {
    super(`Insufficient permission: key lacks ${permission}`, 'INSUFFICIENT_PERMISSION', 403);
  }
}

export class ValidationError extends AuthError {
  constructor(details: string) {
    super(`Validation failed: ${details}`, 'VALIDATION_ERROR', 400);
  }
}

export class RateLimitExceededError extends AuthError {
  constructor(message = 'Rate limit exceeded') {
    super(message, 'RATE_LIMIT_EXCEEDED', 429);
  }
}

export class MfaRequiredError extends AuthError {
  readonly mfaToken: string;

  constructor(mfaToken: string) {
    super('Multi-factor authentication required', 'MFA_REQUIRED', 200);
    this.mfaToken = mfaToken;
  }
}

export class InvalidMfaCodeError extends AuthError {
  constructor(message = 'Invalid or expired MFA verification code') {
    super(message, 'INVALID_MFA_CODE', 400);
  }
}

export class MfaNotConfiguredError extends AuthError {
  constructor() {
    super('MFA is not configured or enabled for this user', 'MFA_NOT_CONFIGURED', 400);
  }
}

export class MfaAlreadyEnabledError extends AuthError {
  constructor() {
    super('MFA is already enabled on this account', 'MFA_ALREADY_ENABLED', 409);
  }
}

export class StepUpRequiredError extends AuthError {
  readonly maxAge: number;

  constructor(maxAge = 300, message = 'Step-up authentication required for high-value action') {
    super(message, 'STEP_UP_REQUIRED', 403);
    this.maxAge = maxAge;
  }
}

export class StepUpTokenExpiredError extends AuthError {
  constructor(message = 'Step-up authentication token has expired or is invalid') {
    super(message, 'STEP_UP_TOKEN_EXPIRED', 403);
  }
}

export class BreachedPasswordError extends AuthError {
  constructor(message = 'The selected password was found in known public data breaches and cannot be used.') {
    super(message, 'PASSWORD_BREACHED', 400);
  }
}

export class NotFoundError extends AuthError {
  constructor(message = 'Resource not found') {
    super(message, 'RESOURCE_NOT_FOUND', 404);
  }
}

export class BadRequestError extends AuthError {
  constructor(message = 'Bad request') {
    super(message, 'BAD_REQUEST', 400);
  }
}

export class ForbiddenError extends AuthError {
  constructor(message = 'Forbidden') {
    super(message, 'FORBIDDEN', 403);
  }
}




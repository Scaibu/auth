import { z } from '@chief-strategist-j/shared-infra';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';

export const UserRoleSchema = z.enum([
  AUTH_CONSTANTS.ROLE_ADMIN,
  AUTH_CONSTANTS.ROLE_MEMBER,
  AUTH_CONSTANTS.ROLE_VIEWER,
]);

export const ApiKeyTypeSchema = z.enum([
  AUTH_CONSTANTS.KEY_TYPE_GENERAL,
  AUTH_CONSTANTS.KEY_TYPE_TESTING,
  AUTH_CONSTANTS.KEY_TYPE_SUPER_SECRET,
]);

export const PasswordValidationSchema = z
  .string({ invalid_type_error: 'Password must be a string' })
  .min(
    AUTH_CONSTANTS.SECURITY_CONFIG.PASSWORD_MIN_LENGTH,
    `Password must be at least ${AUTH_CONSTANTS.SECURITY_CONFIG.PASSWORD_MIN_LENGTH} characters long`
  )
  .regex(
    new RegExp(AUTH_CONSTANTS.SECURITY_CONFIG.PASSWORD_PATTERN),
    'Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character (!@#$%^&*)'
  );

import {
  normalizeUnicodeNFKC,
  detectMixedScripts,
  assertNoHomoglyphSpoof,
} from '../../../shared/utils/unicode-shield.util';

const PROTECTED_RESERVED_NAMES = [
  'admin',
  'administrator',
  'root',
  'owner',
  'support',
  'security',
  'superuser',
  'system',
];

export const SanitizedEmailSchema = z
  .string()
  .transform((val) => normalizeUnicodeNFKC(val).trim().toLowerCase())
  .refine((val) => {
    const mixed = detectMixedScripts(val);
    return !mixed.isMixed;
  }, {
    message: 'E_MIXED_SCRIPT_CONFUSABLE: Mixed-script identifier prohibited for security',
  })
  .refine((val) => {
    const localPart = val.split('@')[0] ?? '';
    try {
      assertNoHomoglyphSpoof(localPart, PROTECTED_RESERVED_NAMES);
      return true;
    } catch {
      return false;
    }
  }, {
    message: 'E_HOMOGLYPH_SPOOF_DETECTED: Email address visually mimics a protected system identity',
  })
  .pipe(z.string().email('Please enter a valid email address'));

export const CreateOrganizationInputSchema = z.object({
  name: z
    .string()
    .transform((val) => normalizeUnicodeNFKC(val).trim())
    .refine((val) => val.length >= 2, 'Organization name must be at least 2 characters long')
    .refine((val) => !detectMixedScripts(val).isMixed, {
      message: 'E_MIXED_SCRIPT_CONFUSABLE: Mixed-script organization name prohibited',
    }),
  slug: z.string().optional(),
});

export const CreateUserInputSchema = z.object({
  email: SanitizedEmailSchema,
  password: PasswordValidationSchema,
  name: z.string().min(2, 'Full name must be at least 2 characters long'),
  org_id: z.string().min(1, 'Target organization ID is required'),
  role: UserRoleSchema.default(AUTH_CONSTANTS.ROLE_MEMBER),
  permissions: z.array(z.string()).default([]),
});

export const SignUpInputSchema = z.object({
  email: SanitizedEmailSchema,
  password: PasswordValidationSchema,
  name: z.string().min(2, 'Full name must be at least 2 characters long'),
  organization_name: z.string().min(2, 'Organization name must be at least 2 characters long'),
  role: UserRoleSchema.default(AUTH_CONSTANTS.ROLE_ADMIN),
});

export const SignInInputSchema = z.object({
  email: SanitizedEmailSchema,
  password: z.string().min(1, 'Password is required'),
  ip_address: z.string().default('127.0.0.1'),
  user_agent: z.string().default('unknown'),
});

export const ForgotPasswordInputSchema = z.object({
  email: SanitizedEmailSchema,
});

export const ResetPasswordInputSchema = z.object({
  token: z.string().min(1, 'Reset token is required'),
  new_password: PasswordValidationSchema,
});

export const ChangePasswordInputSchema = z.object({
  current_password: z.string().min(1, 'Current password is required'),
  new_password: PasswordValidationSchema,
});

export const CreateApiKeyInputSchema = z.object({
  org_id: z.string().min(1, 'Organization ID is required'),
  name: z.string().min(1, 'Key name is required'),
  key_type: ApiKeyTypeSchema.default(AUTH_CONSTANTS.KEY_TYPE_GENERAL),
  permissions: z.array(z.string()).default([
    AUTH_CONSTANTS.PERMISSION_TRACES_READ,
    AUTH_CONSTANTS.PERMISSION_METRICS_READ,
    AUTH_CONSTANTS.PERMISSION_LOGS_READ,
  ]),
  expires_at_ms: z.number().positive().optional(),
  ip_allowlist: z.array(z.string()).default([]),
  rate_quota_rpm: z.number().int().min(1, 'Rate quota must be at least 1 request per minute').max(100000).optional(),
});

export const VerifyApiKeyInputSchema = z.object({
  key: z.string().min(1, 'API key string is required'),
  required_permission: z.string().optional(),
  client_ip: z.string().optional(),
});

export const UpdateUserProfileInputSchema = z.object({
  name: z.string().min(2, 'Full name must be at least 2 characters long').optional(),
});

export const InviteUserInputSchema = z.object({
  email: SanitizedEmailSchema,
  name: z.string().min(2, 'Full name must be at least 2 characters long'),
  role: UserRoleSchema.default(AUTH_CONSTANTS.ROLE_MEMBER),
  permissions: z.array(z.string()).default([]),
});

export const UpdateUserRoleInputSchema = z.object({
  role: UserRoleSchema,
});

export const UpdateUserPermissionsInputSchema = z.object({
  permissions: z.array(z.string()).min(0),
});

export const UpdateOrganizationInputSchema = z.object({
  name: z.string().min(2, 'Organization name must be at least 2 characters long').optional(),
  slug: z.string().min(2, 'Slug must be at least 2 characters long').optional(),
});

export const AuditLogFilterSchema = z.object({
  event_type: z.string().optional(),
  from: z.string().optional(),
  to: z.string().optional(),
});

export const AuditLogRecordSchema = z.object({
  id: z.string().min(1),
  user_id: z.string().min(1),
  org_id: z.string().min(1),
  event_type: z.string().min(1),
  ip_address: z.string().min(1),
  user_agent: z.string().min(1),
  timestamp_ms: z.number().int().positive(),
});

export const AuthUserEntitySchema = z.object({
  id: z.string().min(1),
  email: z.string().email(),
  password_hash: z.string().min(1),
  name: z.string().min(1),
  org_id: z.string().min(1),
  org_name: z.string().min(1),
  role: UserRoleSchema,
  blocked: z.boolean().default(false),
  user_permissions: z.array(z.string()).default([]),
  email_verified: z.boolean().default(false).optional(),
  mfa_enabled: z.boolean().default(false).optional(),
  mfa_secret: z.string().nullable().optional(),
  mfa_enrolled_at_ms: z.number().int().nullable().optional(),
  name_encrypted: z.string().nullable().optional(),
  email_encrypted: z.string().nullable().optional(),
  email_blind_index: z.string().nullable().optional(),
  mfa_secret_encrypted: z.string().nullable().optional(),
});

export const MfaVerifyInputSchema = z.object({
  code: z.string().min(6).max(8, 'Verification code must be 6 digits (or recovery code)'),
});

export const MfaChallengeInputSchema = z.object({
  mfa_token: z.string().min(1, 'MFA challenge token is required'),
  code: z.string().min(6, 'TOTP code or recovery code is required'),
});


export const ApiKeyEntitySchema = z.object({
  key_id: z.string().min(1),
  org_id: z.string().min(1),
  key_type: ApiKeyTypeSchema,
  key_hash: z.string().min(1),
  prefix: z.string().min(1),
  name: z.string().min(1),
  permissions: z.array(z.string()),
  created_at_ms: z.number().int().positive(),
  revoked: z.boolean(),
  expires_at_ms: z.number().int().positive().nullable().optional(),
  last_used_at_ms: z.number().int().positive().nullable().optional(),
  last_used_ip: z.string().nullable().optional(),
  ip_allowlist: z.array(z.string()).default([]),
  rate_quota_rpm: z.number().int().positive().nullable().optional(),
  total_requests_count: z.number().int().nonnegative().default(0),
  anomaly_flag: z.boolean().default(false),
  anomaly_flagged_at_ms: z.number().int().positive().nullable().optional(),
});

export const VerifyEmailInputSchema = z.object({
  token: z.string().min(1, 'Verification token is required'),
});

export const ResendVerificationInputSchema = z.object({
  email: z.string().email('Please enter a valid email address'),
});

export const PasskeyRegisterStartInputSchema = z.object({
  user_id: z.string().optional(),
  friendly_name: z.string().max(128).optional(),
});

export const PasskeyRegisterFinishInputSchema = z.object({
  challenge_id: z.string().min(1, 'Challenge ID is required'),
  credential: z.object({
    id: z.string().min(1, 'Credential ID is required'),
    rawId: z.string().optional(),
    response: z.object({
      clientDataJSON: z.string().min(1, 'clientDataJSON is required'),
      attestationObject: z.string().min(1, 'attestationObject is required'),
      transports: z.array(z.string()).optional(),
    }),
    type: z.literal('public-key'),
  }),
  friendly_name: z.string().max(128).optional(),
});

export const PasskeyAuthStartInputSchema = z.object({
  email: z.string().email('Please enter a valid email address').optional(),
});

export const PasskeyAuthFinishInputSchema = z.object({
  challenge_id: z.string().min(1, 'Challenge ID is required'),
  credential: z.object({
    id: z.string().min(1, 'Credential ID is required'),
    rawId: z.string().optional(),
    response: z.object({
      clientDataJSON: z.string().min(1, 'clientDataJSON is required'),
      authenticatorData: z.string().min(1, 'authenticatorData is required'),
      signature: z.string().min(1, 'signature is required'),
      userHandle: z.string().nullable().optional(),
    }),
    type: z.literal('public-key'),
  }),
});

export const CreateCustomRoleInputSchema = z.object({
  name: z.string().min(1, 'Role name is required').max(64, 'Role name cannot exceed 64 characters'),
  description: z.string().max(255).default(''),
  permission_mask: z.string().regex(/^\d+$/, 'Permission mask must be a numeric string representing a 64-bit unsigned integer'),
});

export const UpdateCustomRoleInputSchema = z.object({
  name: z.string().min(1).max(64).optional(),
  description: z.string().max(255).optional(),
  permission_mask: z.string().regex(/^\d+$/).optional(),
});

export const AssignUserRolesInputSchema = z.object({
  role_ids: z.array(z.string().min(1)),
});

export const EvaluatePermissionsInputSchema = z.object({
  user_id: z.string().min(1, 'User ID is required'),
  org_id: z.string().min(1, 'Org ID is required'),
  required_permissions: z.array(z.string().min(1)).min(1, 'At least one required permission must be specified'),
});

export const SendMagicLinkInputSchema = z.object({
  email: z.string().email('Valid email address is required').transform((e) => e.trim().toLowerCase()),
  redirect_url: z.string().url('Redirect URL must be a valid URL').max(512).optional(),
});

export const ConsumeMagicLinkInputSchema = z.object({
  token: z.string().min(32, 'Valid token is required').max(128),
});

export const AUTH_JSON_MAPPING = {
  fromApi: [
    { op: 'rename', from: 'emailAddress', to: 'email' },
    { op: 'rename', from: 'organizationId', to: 'org_id' },
    { op: 'rename', from: 'organizationName', to: 'org_name' },
  ],
  toApi: [
    { op: 'rename', from: 'email', to: 'emailAddress' },
    { op: 'rename', from: 'org_id', to: 'organizationId' },
    { op: 'rename', from: 'org_name', to: 'organizationName' },
  ],
} as const;

import { z } from '@chief-strategist-j/shared-infra';
import { AUTH_CONSTANTS } from '../constants/auth.constants';

export const UserRoleSchema = z.enum([
  AUTH_CONSTANTS.ROLE_ADMIN,
  AUTH_CONSTANTS.ROLE_MEMBER,
  AUTH_CONSTANTS.ROLE_VIEWER,
]);
export type UserRole = z.infer<typeof UserRoleSchema>;

export const ApiKeyTypeSchema = z.enum([
  AUTH_CONSTANTS.KEY_TYPE_GENERAL,
  AUTH_CONSTANTS.KEY_TYPE_TESTING,
  AUTH_CONSTANTS.KEY_TYPE_SUPER_SECRET,
]);
export type ApiKeyType = z.infer<typeof ApiKeyTypeSchema>;

export const TenantContextSchema = z.object({
  org_id: z.string().min(1),
  org_name: z.string().min(1),
  role: UserRoleSchema,
});
export type TenantContext = z.infer<typeof TenantContextSchema>;

export const AuthTokenPayloadSchema = z.object({
  sub: z.string().min(1),
  email: z.string().email(),
  org: TenantContextSchema,
  exp: z.number().positive(),
  iat: z.number().positive(),
  jti: z.string().optional(),
});
export type AuthTokenPayload = z.infer<typeof AuthTokenPayloadSchema>;

export const ApiKeyRecordSchema = z.object({
  key_id: z.string().min(1),
  org_id: z.string().min(1),
  key_type: ApiKeyTypeSchema,
  key_hash: z.string().min(1),
  prefix: z.string().min(1),
  name: z.string().min(1),
  permissions: z.array(z.string()),
  created_at_ms: z.number().positive(),
  revoked: z.boolean(),
  expires_at_ms: z.number().positive().nullable().optional(),
  last_used_at_ms: z.number().positive().nullable().optional(),
  last_used_ip: z.string().nullable().optional(),
});
export type ApiKeyRecord = z.infer<typeof ApiKeyRecordSchema>;

export const UserDsarExportPayloadSchema = z.object({
  export_metadata: z.object({
    format_version: z.string(),
    compliance_standard: z.string(),
    exported_at: z.string(),
    data_subject_id: z.string(),
  }),
  profile: z.object({
    id: z.string(),
    email: z.string(),
    name: z.string(),
    role: z.string(),
    email_verified: z.boolean(),
    mfa_enabled: z.boolean(),
    mfa_enrolled_at: z.string().nullable().optional(),
    permissions: z.array(z.string()),
  }),
  organizations: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      slug: z.string(),
      role: z.string(),
    })
  ),
  api_keys: z.array(
    z.object({
      key_id: z.string(),
      name: z.string(),
      key_type: z.string(),
      created_at: z.string(),
      last_used_at: z.string().nullable().optional(),
      last_used_ip: z.string().nullable().optional(),
    })
  ),
  audit_logs: z.array(
    z.object({
      id: z.string(),
      event_type: z.string(),
      ip_address: z.string(),
      timestamp: z.string(),
    })
  ),
});
export type UserDsarExportPayload = z.infer<typeof UserDsarExportPayloadSchema>;

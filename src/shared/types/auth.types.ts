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

export const UserSessionSummarySchema = z.object({
  id: z.string(),
  ip_address: z.string().nullable().optional(),
  user_agent: z.string().nullable().optional(),
  created_at: z.string(),
  last_active_at: z.string(),
  is_current: z.boolean(),
});
export type UserSessionSummary = z.infer<typeof UserSessionSummarySchema>;

export const FederatedIdentityRecordSchema = z.object({
  id: z.string().min(1),
  user_id: z.string().min(1),
  provider: z.string().min(1),
  provider_subject_id: z.string().min(1),
  email: z.string().email(),
  created_at_ms: z.number().int().positive(),
  updated_at_ms: z.number().int().positive(),
});
export type FederatedIdentityRecord = z.infer<typeof FederatedIdentityRecordSchema>;

export const FederatedUserProfileSchema = z.object({
  provider: z.string().min(1),
  provider_subject_id: z.string().min(1),
  email: z.string().email(),
  email_verified: z.boolean(),
  name: z.string().min(1),
});
export type FederatedUserProfile = z.infer<typeof FederatedUserProfileSchema>;

export const DomainStatusSchema = z.enum([
  AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_PENDING,
  AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_VERIFIED,
  AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_SUSPENDED,
]);
export type DomainStatus = z.infer<typeof DomainStatusSchema>;

export const ClaimedDomainRecordSchema = z.object({
  id: z.string().min(1),
  org_id: z.string().min(1),
  domain_name: z.string().min(1),
  status: DomainStatusSchema,
  verification_token: z.string().min(1),
  verification_method: z.string().min(1),
  default_role: z.string().min(1),
  auto_join_enabled: z.boolean(),
  created_at_ms: z.number().int().positive(),
  verified_at_ms: z.number().int().positive().nullable().optional(),
  last_checked_at_ms: z.number().int().positive().nullable().optional(),
});
export type ClaimedDomainRecord = z.infer<typeof ClaimedDomainRecordSchema>;

export const BlockedDomainRecordSchema = z.object({
  domain_name: z.string().min(1),
  category: z.string().min(1),
  reason: z.string().nullable().optional(),
  created_at_ms: z.number().int().positive(),
  updated_at_ms: z.number().int().positive(),
});
export type BlockedDomainRecord = z.infer<typeof BlockedDomainRecordSchema>;

export const RelationTupleSchema = z.object({
  id: z.string().min(1),
  org_id: z.string().min(1),
  subject_type: z.string().min(1),
  subject_id: z.string().min(1),
  relation: z.string().min(1),
  object_type: z.string().min(1),
  object_id: z.string().min(1),
  conditions: z.record(z.unknown()).default({}),
  status: z.enum(['ACTIVE', 'SUSPENDED', 'EXPIRED', 'REVOKED']).default('ACTIVE'),
  expires_at_ms: z.number().int().positive().nullable().optional(),
  granted_by: z.string().nullable().optional(),
  version: z.number().int().positive().default(1),
  created_at_ms: z.number().int().positive(),
  updated_at_ms: z.number().int().positive().optional(),
  deleted_at_ms: z.number().int().positive().nullable().optional(),
});
export type RelationTuple = z.infer<typeof RelationTupleSchema>;

export const PolicyEvaluationRequestSchema = z.object({
  subject_type: z.string().min(1),
  subject_id: z.string().min(1),
  action: z.string().min(1),
  object_type: z.string().min(1),
  object_id: z.string().min(1),
  context: z.record(z.unknown()).optional(),
});
export type PolicyEvaluationRequest = z.infer<typeof PolicyEvaluationRequestSchema>;

export const PolicyEvaluationResultSchema = z.object({
  allowed: z.boolean(),
  reason: z.string(),
  decision: z.string(),
  evaluated_at: z.string(),
});
export type PolicyEvaluationResult = z.infer<typeof PolicyEvaluationResultSchema>;



import { z } from '@chief-strategist-j/shared-infra';
import {
  SignUpInputSchema,
  SignInInputSchema,
  AuthUserEntitySchema,
  AuditLogRecordSchema,
  ForgotPasswordInputSchema,
  ResetPasswordInputSchema,
  ChangePasswordInputSchema,
  CreateApiKeyInputSchema,
  VerifyApiKeyInputSchema,
  CreateOrganizationInputSchema,
  CreateUserInputSchema,
  UpdateUserProfileInputSchema,
  InviteUserInputSchema,
  UpdateUserRoleInputSchema,
  UpdateUserPermissionsInputSchema,
  UpdateOrganizationInputSchema,
  AuditLogFilterSchema,
  VerifyEmailInputSchema,
  ResendVerificationInputSchema,
  MfaVerifyInputSchema,
  MfaChallengeInputSchema,
} from './schema/auth.schema';

export type CreateOrganizationInput = z.input<typeof CreateOrganizationInputSchema>;
export type CreateUserInput = z.input<typeof CreateUserInputSchema>;
export type SignUpInput = z.input<typeof SignUpInputSchema>;
export type SignInInput = z.input<typeof SignInInputSchema>;
export type AuthUserRecord = z.infer<typeof AuthUserEntitySchema>;
export type AuditLogRecord = z.infer<typeof AuditLogRecordSchema>;
export type ForgotPasswordInput = z.input<typeof ForgotPasswordInputSchema>;
export type ResetPasswordInput = z.input<typeof ResetPasswordInputSchema>;
export type ChangePasswordInput = z.input<typeof ChangePasswordInputSchema>;
export type CreateApiKeyInput = z.input<typeof CreateApiKeyInputSchema>;
export type VerifyApiKeyInput = z.input<typeof VerifyApiKeyInputSchema>;
export type UpdateUserProfileInput = z.input<typeof UpdateUserProfileInputSchema>;
export type InviteUserInput = z.input<typeof InviteUserInputSchema>;
export type UpdateUserRoleInput = z.input<typeof UpdateUserRoleInputSchema>;
export type UpdateUserPermissionsInput = z.input<typeof UpdateUserPermissionsInputSchema>;
export type UpdateOrganizationInput = z.input<typeof UpdateOrganizationInputSchema>;
export type AuditLogFilter = z.input<typeof AuditLogFilterSchema>;
export type VerifyEmailInput = z.input<typeof VerifyEmailInputSchema>;
export type ResendVerificationInput = z.input<typeof ResendVerificationInputSchema>;
export type MfaVerifyInput = z.input<typeof MfaVerifyInputSchema>;
export type MfaChallengeInput = z.input<typeof MfaChallengeInputSchema>;

export interface GeoLocationTelemetry {
  readonly ip: string;
  readonly latitude?: number;
  readonly longitude?: number;
  readonly asn?: string;
  readonly isDatacenter?: boolean;
}

export interface LoginHistoryRecord {
  readonly id: string;
  readonly userId: string;
  readonly ipAddress: string;
  readonly latitude?: number;
  readonly longitude?: number;
  readonly asn?: string;
  readonly isDatacenter: boolean;
  readonly deviceFingerprint: string;
  readonly riskScore: number;
  readonly createdAtMs: number;
}

export interface RiskEvaluationResult {
  readonly riskScore: number;
  readonly reasons: readonly string[];
  readonly requiresStepUp: boolean;
  readonly isBlocked: boolean;
  readonly currentTelemetry: GeoLocationTelemetry & { readonly deviceFingerprint: string };
}

export interface ResolveChallengeInput {
  readonly challenge_token: string;
  readonly verification_code: string;
}



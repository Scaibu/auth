import type { AuthUserRecord, AuditLogRecord } from './types';
import type { ApiKeyRecord, FederatedIdentityRecord } from '../../shared/types/auth.types';

export interface OrganizationRecord {
  id: string;
  name: string;
  slug: string;
  deleted_at?: number;
}

export interface AuthRepositoryPort {
  createOrganization(org: OrganizationRecord, creatorUserId?: string): Promise<void>;
  listOrganizationsByUserId(userId: string): Promise<OrganizationRecord[]>;
  getOrganizationById(orgId: string): Promise<OrganizationRecord | null>;
  updateOrganization(orgId: string, patch: { name?: string; slug?: string }): Promise<void>;
  deleteOrganization(orgId: string): Promise<void>;
  createUser(userRecord: AuthUserRecord): Promise<void>;
  listUsersByOrgId(orgId: string): Promise<AuthUserRecord[]>;
  blockUser(userId: string): Promise<void>;
  unblockUser(userId: string): Promise<void>;
  deleteUser(userId: string): Promise<void>;
  updateUserProfile(userId: string, patch: { name?: string }): Promise<void>;
  updateUserRole(userId: string, role: string): Promise<void>;
  updateUserPermissions(userId: string, permissions: string[]): Promise<void>;
  purgeExpiredSoftDeletes(): Promise<number>;
  findUserByEmail(email: string): Promise<AuthUserRecord | null>;
  findUserById(id: string): Promise<AuthUserRecord | null>;
  createOrganizationAndUser(userRecord: AuthUserRecord): Promise<void>;
  recordAuditLog(logRecord: AuditLogRecord): Promise<void>;
  savePasswordResetToken(tokenHash: string, userId: string, expiresAtMs: number): Promise<void>;
  findPasswordResetToken(tokenHash: string): Promise<{ tokenHash: string; userId: string; expiresAtMs: number; used: boolean } | null>;
  updateUserPassword(userId: string, newPasswordHash: string): Promise<void>;
  markPasswordResetTokenUsed(tokenHash: string): Promise<void>;
  saveApiKey(keyRecord: ApiKeyRecord): Promise<void>;
  listApiKeysByOrgId(orgId: string): Promise<ApiKeyRecord[]>;
  findApiKeyByHash(hash: string): Promise<ApiKeyRecord | null>;
  revokeApiKey(keyId: string): Promise<void>;
  updateApiKeyUsage(keyId: string, lastUsedAtMs: number, lastUsedIp?: string): Promise<void>;
  saveEmailVerificationToken(tokenHash: string, userId: string, email: string, expiresAtMs: number): Promise<void>;
  findEmailVerificationToken(tokenHash: string): Promise<{ tokenHash: string; userId: string; email: string; expiresAtMs: number; used: boolean } | null>;
  markEmailVerified(tokenHash: string, userId: string): Promise<void>;
  fetchUserAuditLogs(userId: string, filters?: { event_type?: string; from_ms?: number; to_ms?: number }): Promise<AuditLogRecord[]>;
  addTokenToDenylist(token: string, expiresAtMs: number): Promise<void>;
  isTokenDenylisted(token: string): Promise<boolean>;
  setMfaSecret(userId: string, secret: string): Promise<void>;
  enableMfa(userId: string, enrolledAtMs: number): Promise<void>;
  saveRecoveryCodes(userId: string, codeHashes: string[]): Promise<void>;
  findRecoveryCode(userId: string, codeHash: string): Promise<{ id: string; user_id: string; code_hash: string; used: boolean } | null>;
  consumeRecoveryCode(id: string, usedAtMs: number): Promise<void>;
  createRefreshTokenFamily(familyId: string, userId: string, createdAtMs: number): Promise<void>;
  findRefreshTokenFamily(familyId: string): Promise<{ id: string; user_id: string; is_revoked: boolean; revoked_reason?: string } | null>;
  revokeRefreshTokenFamily(familyId: string, reason: string): Promise<void>;
  saveRefreshToken(token: {
    tokenId: string;
    familyId: string;
    userId: string;
    tokenHash: string;
    generation: number;
    expiresAtMs: number;
    createdAtMs: number;
    createdIp?: string;
    userAgent?: string;
  }): Promise<void>;
  findRefreshTokenByHash(tokenHash: string): Promise<{
    tokenId: string;
    familyId: string;
    userId: string;
    tokenHash: string;
    generation: number;
    isRevoked: boolean;
    expiresAtMs: number;
    createdAtMs: number;
    consumedAtMs?: number;
  } | null>;
  consumeRefreshToken(tokenId: string, consumedAtMs: number): Promise<void>;
  exportUserData(userId: string): Promise<{
    user: AuthUserRecord;
    organizations: OrganizationRecord[];
    apiKeys: ApiKeyRecord[];
    auditLogs: AuditLogRecord[];
  } | null>;
  listActiveSessionsByUserId(userId: string): Promise<Array<{
    familyId: string;
    userId: string;
    createdAtMs: number;
    lastActiveAtMs: number;
    createdIp?: string;
    userAgent?: string;
  }>>;
  revokeOtherSessionsByUserId(userId: string, currentFamilyId: string, reason: string): Promise<number>;
  findFederatedIdentity(provider: string, providerSubjectId: string): Promise<FederatedIdentityRecord | null>;
  findFederatedIdentityByUserAndProvider(userId: string, provider: string): Promise<FederatedIdentityRecord | null>;
  listFederatedIdentitiesByUserId(userId: string): Promise<FederatedIdentityRecord[]>;
  saveFederatedIdentity(identity: FederatedIdentityRecord): Promise<void>;
  deleteFederatedIdentity(userId: string, provider: string): Promise<void>;
  countFederatedIdentitiesByUserId(userId: string): Promise<number>;
}



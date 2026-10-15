import type { AuthUserRecord, AuditLogRecord } from './types';
import type { ApiKeyRecord, FederatedIdentityRecord, ClaimedDomainRecord, BlockedDomainRecord, RelationTuple, CustomRoleRecord } from '../../shared/types/auth.types';
import type { SamlRepositoryPort } from './ports/saml-repository.port';

export interface OrganizationRecord {
  id: string;
  name: string;
  slug: string;
  deleted_at?: number;
}

export interface AuthRepositoryPort extends SamlRepositoryPort {

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
  recordPasswordHistory(userId: string, passwordHash: string, createdAtMs?: number): Promise<void>;
  getRecentPasswordHashes(userId: string, limit?: number): Promise<string[]>;
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
  saveClaimedDomain(domainRecord: ClaimedDomainRecord): Promise<void>;
  findClaimedDomainById(domainId: string): Promise<ClaimedDomainRecord | null>;
  findClaimedDomainByName(domainName: string): Promise<ClaimedDomainRecord | null>;
  listClaimedDomainsByOrgId(orgId: string): Promise<ClaimedDomainRecord[]>;
  updateClaimedDomainStatus(domainId: string, status: string, verifiedAtMs?: number): Promise<void>;
  updateClaimedDomainSettings(domainId: string, autoJoinEnabled: boolean, defaultRole: string): Promise<void>;
  deleteClaimedDomain(domainId: string): Promise<void>;
  listPendingOrVerifiedDomains(): Promise<ClaimedDomainRecord[]>;
  findBlockedDomain(domainName: string): Promise<BlockedDomainRecord | null>;
  listBlockedDomains(): Promise<BlockedDomainRecord[]>;
  saveBlockedDomain(record: BlockedDomainRecord): Promise<void>;
  deleteBlockedDomain(domainName: string): Promise<void>;
  recordLoginHistory(record: {
    id: string;
    userId: string;
    ipAddress: string;
    latitude?: number;
    longitude?: number;
    asn?: string;
    isDatacenter: boolean;
    deviceFingerprint: string;
    riskScore: number;
    createdAtMs: number;
  }): Promise<void>;
  getLatestLoginLocation(userId: string): Promise<{
    id: string;
    userId: string;
    ipAddress: string;
    latitude?: number;
    longitude?: number;
    asn?: string;
    isDatacenter: boolean;
    deviceFingerprint: string;
    riskScore: number;
    createdAtMs: number;
  } | null>;
  saveRelationTuple(tuple: RelationTuple): Promise<void>;
  deleteRelationTuple(
    orgId: string,
    subjectType: string,
    subjectId: string,
    relation: string,
    objectType: string,
    objectId: string,
  ): Promise<boolean>;
  findRelationTuples(
    orgId: string,
    filter?: {
      subject_type?: string;
      subject_id?: string;
      relation?: string;
      object_type?: string;
      object_id?: string;
    },
  ): Promise<RelationTuple[]>;
  saveScimToken(record: { id: string; org_id: string; token_hash: string; description: string; status: 'ACTIVE' | 'REVOKED'; created_at_ms: number; expires_at_ms: number | null; last_used_at_ms: number | null }): Promise<void>;
  findScimTokenByHash(tokenHash: string): Promise<{ id: string; org_id: string; token_hash: string; description: string; status: 'ACTIVE' | 'REVOKED'; created_at_ms: number; expires_at_ms: number | null; last_used_at_ms: number | null } | null>;
  saveExternalMapping(orgId: string, resourceType: 'user' | 'group', internalId: string, externalId: string): Promise<void>;
  findExternalMapping(orgId: string, resourceType: 'user' | 'group', externalId: string): Promise<string | null>;
  saveScimGroup(orgId: string, group: { id: string; displayName: string; externalId?: string }): Promise<void>;
  findScimGroupById(orgId: string, groupId: string): Promise<{ id: string; externalId?: string; displayName: string; members: ReadonlyArray<{ value: string; display?: string }>; meta: { resourceType: 'Group'; created: string; lastModified: string; location: string } } | null>;
  listScimGroups(orgId: string, filter?: string, startIndex?: number, count?: number): Promise<{ groups: ReadonlyArray<{ id: string; externalId?: string; displayName: string; members: ReadonlyArray<{ value: string; display?: string }>; meta: { resourceType: 'Group'; created: string; lastModified: string; location: string } }>; total: number }>;
  deleteScimGroup(orgId: string, groupId: string): Promise<void>;
  addScimGroupMember(groupId: string, userId: string): Promise<void>;
  removeScimGroupMember(groupId: string, userId: string): Promise<void>;
  listScimGroupMembers(groupId: string): Promise<ReadonlyArray<{ value: string; display?: string }>>;
  saveOAuthClient(client: { id: string; org_id: string; client_name: string; client_secret_hash?: string; redirect_uris: ReadonlyArray<string>; grant_types: ReadonlyArray<string>; response_types: ReadonlyArray<string>; client_type: 'public' | 'confidential'; status: 'ACTIVE' | 'SUSPENDED'; created_at_ms: number }): Promise<void>;
  findOAuthClientById(clientId: string): Promise<{ id: string; org_id: string; client_name: string; client_secret_hash?: string; redirect_uris: ReadonlyArray<string>; grant_types: ReadonlyArray<string>; response_types: ReadonlyArray<string>; client_type: 'public' | 'confidential'; status: 'ACTIVE' | 'SUSPENDED'; created_at_ms: number } | null>;
  saveAuthorizationCode(codeRecord: { code: string; client_id: string; user_id: string; org_id: string; redirect_uri: string; code_challenge: string; code_challenge_method: 'S256'; scope: string; used: boolean; expires_at_ms: number; created_at_ms: number }): Promise<void>;
  findAuthorizationCode(code: string): Promise<{ code: string; client_id: string; user_id: string; org_id: string; redirect_uri: string; code_challenge: string; code_challenge_method: 'S256'; scope: string; used: boolean; expires_at_ms: number; created_at_ms: number } | null>;
  consumeAuthorizationCode(code: string): Promise<void>;
  saveSigningKey(key: { kid: string; kty: string; alg: string; use: string; public_key_pem: string; private_key_pem: string; status: 'ACTIVE' | 'RETIRED'; created_at_ms: number }): Promise<void>;
  getActiveSigningKey(): Promise<{ kid: string; kty: string; alg: string; use: string; public_key_pem: string; private_key_pem: string; status: 'ACTIVE' | 'RETIRED'; created_at_ms: number } | null>;
  updateApiKeyAllowlist(keyId: string, ipAllowlist: readonly string[]): Promise<{ key_id: string; org_id: string; ip_allowlist: string[]; rate_quota_rpm: number | null } | null>;
  findApiKeyMeta(keyId: string): Promise<{ key_id: string; org_id: string; ip_allowlist: string[]; rate_quota_rpm: number | null; anomaly_flag: boolean } | null>;
  flagApiKeyAnomaly(keyId: string, flaggedAtMs: number): Promise<void>;
  savePasskeyChallenge(record: { challenge_id: string; user_id?: string | null; challenge: string; origin: string; rp_id: string; challenge_type: 'registration' | 'authentication'; expires_at_ms: number; created_at_ms: number }): Promise<void>;
  findPasskeyChallenge(challengeId: string): Promise<{ challenge_id: string; user_id?: string | null; challenge: string; origin: string; rp_id: string; challenge_type: 'registration' | 'authentication'; expires_at_ms: number; created_at_ms: number } | null>;
  consumePasskeyChallenge(challengeId: string): Promise<void>;
  savePasskeyCredential(record: { id: string; credential_id: string; user_id: string; org_id: string; public_key: string; counter: number; device_type: string; backed_up: boolean; transports: string[]; aaguid?: string | null; friendly_name: string; created_at_ms: number }): Promise<void>;
  findPasskeyCredentialById(credentialId: string): Promise<{ id: string; credential_id: string; user_id: string; org_id: string; public_key: string; counter: number; device_type: string; backed_up: boolean; transports: string[]; aaguid?: string | null; friendly_name: string; created_at_ms: number; last_used_at_ms?: number | null } | null>;
  listPasskeysByUserId(userId: string): Promise<Array<{ id: string; credential_id: string; user_id: string; org_id: string; public_key: string; counter: number; device_type: string; backed_up: boolean; transports: string[]; aaguid?: string | null; friendly_name: string; created_at_ms: number; last_used_at_ms?: number | null }>>;
  updatePasskeyCounter(credentialId: string, counter: number, lastUsedAtMs: number): Promise<void>;
  deletePasskey(passkeyId: string, userId: string): Promise<void>;
  saveCustomRole(role: CustomRoleRecord): Promise<void>;
  findCustomRoleById(id: string, orgId: string): Promise<CustomRoleRecord | null>;
  findCustomRoleByName(name: string, orgId: string): Promise<CustomRoleRecord | null>;
  listCustomRolesByOrgId(orgId: string): Promise<CustomRoleRecord[]>;
  updateCustomRole(id: string, orgId: string, patch: { name?: string; description?: string; permission_mask?: string }): Promise<void>;
  deleteCustomRole(id: string, orgId: string): Promise<void>;
  assignUserCustomRoles(orgId: string, userId: string, roleIds: readonly string[], assignedBy?: string): Promise<void>;
  listUserCustomRoles(orgId: string, userId: string): Promise<CustomRoleRecord[]>;
  recordRoleAuditLog(log: { id: string; org_id: string; actor_user_id: string; action: string; target_role_id: string; target_user_id?: string; previous_mask?: string; new_mask?: string; reason?: string; created_at_ms: number }): Promise<void>;
}




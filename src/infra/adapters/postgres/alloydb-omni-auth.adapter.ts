import type { AuthRepositoryPort, OrganizationRecord } from '../../../features/auth/repository';
import type { AuthUserRecord, AuditLogRecord } from '../../../features/auth/types';
import type { ApiKeyRecord, FederatedIdentityRecord, ClaimedDomainRecord, BlockedDomainRecord, RelationTuple } from '../../../shared/types/auth.types';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { AUTH_QUERIES } from '../../../features/auth/queries/auth.queries';

export class AlloyDBOmniAuthAdapter implements AuthRepositoryPort {
  private readonly mockOrgs = new Map<string, OrganizationRecord>();
  private readonly mockUsers = new Map<string, AuthUserRecord & { deleted_at?: number; email_verified?: boolean }>();
  private readonly mockUserOrgs = new Map<string, Set<string>>();
  private readonly mockApiKeys = new Map<string, ApiKeyRecord & { deleted_at?: number }>();
  private readonly mockAuditLogs = new Map<string, AuditLogRecord & { deleted_at?: number }>();
  private readonly mockResets = new Map<string, { tokenHash: string; userId: string; expiresAtMs: number; used: boolean; deleted_at?: number }>();
  private readonly mockEmailVerifications = new Map<string, { tokenHash: string; userId: string; email: string; expiresAtMs: number; used: boolean; deleted_at?: number }>();
  private readonly tokenDenylist = new Map<string, number>();
  private readonly mockRecoveryCodes = new Map<string, { id: string; user_id: string; code_hash: string; used: boolean; used_at_ms?: number }>();
  private readonly mockRefreshFamilies = new Map<string, { id: string; user_id: string; is_revoked: boolean; revoked_reason?: string; created_at_ms: number }>();
  private readonly mockRefreshTokens = new Map<string, {
    tokenId: string;
    familyId: string;
    userId: string;
    tokenHash: string;
    generation: number;
    isRevoked: boolean;
    expiresAtMs: number;
    createdAtMs: number;
    consumedAtMs?: number;
    createdIp?: string;
    userAgent?: string;
  }>();
  private readonly mockClaimedDomains = new Map<string, ClaimedDomainRecord & { deleted_at?: number }>();
  private readonly mockSamlProviders = new Map<string, any>();
  private readonly mockSamlRequests = new Map<string, any>();
  private readonly mockSamlAssertionReplay = new Map<string, number>();
  private readonly mockPasswordHistory = new Map<string, Array<{ id: string; password_hash: string; created_at_ms: number }>>();
  public readonly queries = AUTH_QUERIES;


  constructor() {
    this.mockOrgs.set(AUTH_CONSTANTS.DEFAULT_ORG_ID, {
      id: AUTH_CONSTANTS.DEFAULT_ORG_ID,
      name: AUTH_CONSTANTS.DEFAULT_ORG_NAME,
      slug: 'acme-observability',
    });

    this.mockUsers.set(AUTH_CONSTANTS.DEFAULT_ADMIN_EMAIL, {
      id: AUTH_CONSTANTS.DEFAULT_ADMIN_ID,
      email: AUTH_CONSTANTS.DEFAULT_ADMIN_EMAIL,
      password_hash: AUTH_CONSTANTS.DEFAULT_ADMIN_PASSWORD_HASH,
      name: AUTH_CONSTANTS.DEFAULT_ADMIN_NAME,
      org_id: AUTH_CONSTANTS.DEFAULT_ORG_ID,
      org_name: AUTH_CONSTANTS.DEFAULT_ORG_NAME,
      role: AUTH_CONSTANTS.ROLE_ADMIN,
      blocked: false,
      user_permissions: [AUTH_CONSTANTS.PERMISSION_ADMIN_ALL],
    });

    this.mockUserOrgs.set(AUTH_CONSTANTS.DEFAULT_ADMIN_ID, new Set([AUTH_CONSTANTS.DEFAULT_ORG_ID]));

    const now = Date.now();
    for (const domain of AUTH_CONSTANTS.DOMAIN_CLAIM.CANONICAL_BLOCKED_DOMAINS) {
      this.mockBlockedDomains.set(domain, {
        domain_name: domain,
        category: AUTH_CONSTANTS.DOMAIN_CLAIM.CATEGORY_FREEMAIL,
        reason: AUTH_CONSTANTS.DOMAIN_CLAIM.CATEGORY_FREEMAIL,
        created_at_ms: now,
        updated_at_ms: now,
      });
    }
  }


  public getFlowQuery(flow: keyof typeof AUTH_QUERIES): string {
    return JSON.stringify(this.queries[flow]);
  }

  async createOrganization(org: OrganizationRecord, creatorUserId?: string): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_CREATE_ORGANIZATION);
    const existing = [...this.mockOrgs.values()].find((o) => !o.deleted_at && o.name.toLowerCase() === org.name.toLowerCase());
    if (existing) {
      throw new Error(`${AUTH_CONSTANTS.ERROR_MESSAGES.ORG_ALREADY_EXISTS_PREFIX}${org.name}`);
    }
    this.mockOrgs.set(org.id, { ...org });
    if (creatorUserId) {
      if (!this.mockUserOrgs.has(creatorUserId)) this.mockUserOrgs.set(creatorUserId, new Set());
      this.mockUserOrgs.get(creatorUserId)!.add(org.id);
    }
  }

  async listOrganizationsByUserId(userId: string): Promise<OrganizationRecord[]> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_CREATE_ORGANIZATION);
    const orgIds = this.mockUserOrgs.get(userId) ?? new Set();
    const user = [...this.mockUsers.values()].find((u) => u.id === userId && !u.deleted_at);
    if (user) orgIds.add(user.org_id);

    const result: OrganizationRecord[] = [];
    for (const orgId of orgIds) {
      const org = this.mockOrgs.get(orgId);
      if (org && !org.deleted_at) result.push(org);
    }
    return result;
  }

  async getOrganizationById(orgId: string): Promise<OrganizationRecord | null> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_CREATE_ORGANIZATION);
    const org = this.mockOrgs.get(orgId);
    if (!org || org.deleted_at) return null;
    return org;
  }

  async updateOrganization(orgId: string, patch: { name?: string; slug?: string }): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_CREATE_ORGANIZATION);
    const org = this.mockOrgs.get(orgId);
    if (org && !org.deleted_at) {
      if (patch.name) org.name = patch.name;
      if (patch.slug) org.slug = patch.slug;
    }
  }

  async deleteOrganization(orgId: string): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_DELETE_ORGANIZATION);
    const now = Date.now();
    const org = this.mockOrgs.get(orgId);
    if (org) org.deleted_at = now;

    for (const user of this.mockUsers.values()) {
      if (user.org_id === orgId) user.deleted_at = now;
    }
    for (const key of this.mockApiKeys.values()) {
      if (key.org_id === orgId) key.deleted_at = now;
    }
    for (const log of this.mockAuditLogs.values()) {
      if (log.org_id === orgId) log.deleted_at = now;
    }
  }

  async createUser(userRecord: AuthUserRecord): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_CREATE_USER);
    const existing = [...this.mockUsers.values()].find((u) => !u.deleted_at && u.email === userRecord.email);
    if (existing) {
      throw new Error(`${AUTH_CONSTANTS.ERROR_MESSAGES.USER_ALREADY_EXISTS_PREFIX}${userRecord.email}${AUTH_CONSTANTS.ERROR_MESSAGES.USER_ALREADY_EXISTS_SUFFIX}`);
    }
    this.mockUsers.set(userRecord.email, { ...userRecord });
    if (!this.mockUserOrgs.has(userRecord.id)) this.mockUserOrgs.set(userRecord.id, new Set());
    this.mockUserOrgs.get(userRecord.id)!.add(userRecord.org_id);
  }

  async listUsersByOrgId(orgId: string): Promise<AuthUserRecord[]> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_CREATE_USER);
    return [...this.mockUsers.values()].filter((u) => u.org_id === orgId && !u.deleted_at);
  }

  async blockUser(userId: string): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_BLOCK_USER);
    for (const user of this.mockUsers.values()) {
      if (user.id === userId && !user.deleted_at) {
        user.blocked = true;
      }
    }
  }

  async unblockUser(userId: string): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_BLOCK_USER);
    for (const user of this.mockUsers.values()) {
      if (user.id === userId && !user.deleted_at) {
        user.blocked = false;
      }
    }
  }

  async deleteUser(userId: string): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_DELETE_USER);
    const now = Date.now();
    for (const user of this.mockUsers.values()) {
      if (user.id === userId) {
        user.deleted_at = now;
      }
    }
  }

  async updateUserProfile(userId: string, patch: { name?: string }): Promise<void> {
    for (const user of this.mockUsers.values()) {
      if (user.id === userId && !user.deleted_at) {
        if (patch.name) user.name = patch.name;
      }
    }
  }

  async updateUserRole(userId: string, role: string): Promise<void> {
    for (const user of this.mockUsers.values()) {
      if (user.id === userId && !user.deleted_at) {
        (user as any).role = role;
      }
    }
  }

  async updateUserPermissions(userId: string, permissions: string[]): Promise<void> {
    for (const user of this.mockUsers.values()) {
      if (user.id === userId && !user.deleted_at) {
        user.user_permissions = permissions;
      }
    }
  }

  async purgeExpiredSoftDeletes(): Promise<number> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_RETENTION_PURGE);
    const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
    let purged = 0;

    for (const [id, org] of this.mockOrgs.entries()) {
      if (org.deleted_at && org.deleted_at < cutoff) {
        this.mockOrgs.delete(id);
        purged++;
      }
    }
    for (const [email, user] of this.mockUsers.entries()) {
      if (user.deleted_at && user.deleted_at < cutoff) {
        this.mockUsers.delete(email);
        purged++;
      }
    }
    for (const [key, keyRecord] of this.mockApiKeys.entries()) {
      if (keyRecord.deleted_at && keyRecord.deleted_at < cutoff) {
        this.mockApiKeys.delete(key);
        purged++;
      }
    }
    for (const [token, expiresAtMs] of this.tokenDenylist.entries()) {
      if (expiresAtMs < Date.now()) {
        this.tokenDenylist.delete(token);
      }
    }
    return purged;
  }

  async findUserByEmail(email: string): Promise<AuthUserRecord | null> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_SIGN_IN);
    const user = this.mockUsers.get(email);
    if (!user || user.deleted_at) return null;
    return user;
  }

  async findUserById(id: string): Promise<AuthUserRecord | null> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_SESSION_VERIFY);
    const user = [...this.mockUsers.values()].find((u) => u.id === id && !u.deleted_at);
    return user ?? null;
  }

  async createOrganizationAndUser(userRecord: AuthUserRecord): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_SIGN_UP);
    const existingOrg = [...this.mockOrgs.values()].find((o) => !o.deleted_at && o.name.toLowerCase() === userRecord.org_name.toLowerCase());
    if (existingOrg) {
      throw new Error(`${AUTH_CONSTANTS.ERROR_MESSAGES.ORG_ALREADY_EXISTS_PREFIX}${userRecord.org_name}`);
    }
    this.mockOrgs.set(userRecord.org_id, {
      id: userRecord.org_id,
      name: userRecord.org_name,
      slug: userRecord.org_name.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
    });
    this.mockUsers.set(userRecord.email, { ...userRecord });
    if (!this.mockUserOrgs.has(userRecord.id)) this.mockUserOrgs.set(userRecord.id, new Set());
    this.mockUserOrgs.get(userRecord.id)!.add(userRecord.org_id);
  }

  async recordAuditLog(logRecord: AuditLogRecord): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_SIGN_IN);
    this.mockAuditLogs.set(logRecord.id, logRecord);
  }

  async savePasswordResetToken(tokenHash: string, userId: string, expiresAtMs: number): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_FORGOT_PASSWORD);
    this.mockResets.set(tokenHash, { tokenHash, userId, expiresAtMs, used: false });
  }

  async findPasswordResetToken(tokenHash: string): Promise<{ tokenHash: string; userId: string; expiresAtMs: number; used: boolean } | null> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_FORGOT_PASSWORD);
    const reset = this.mockResets.get(tokenHash);
    if (!reset || reset.deleted_at) return null;
    return reset;
  }

  async updateUserPassword(userId: string, newPasswordHash: string): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_RESET_PASSWORD);
    for (const user of this.mockUsers.values()) {
      if (user.id === userId && !user.deleted_at) {
        user.password_hash = newPasswordHash;
      }
    }
  }

  async recordPasswordHistory(userId: string, passwordHash: string, createdAtMs = Date.now()): Promise<void> {
    const list = this.mockPasswordHistory.get(userId) ?? [];
    const historyId = `pwh_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    list.unshift({ id: historyId, password_hash: passwordHash, created_at_ms: createdAtMs });
    if (list.length > 10) {
      list.length = 10;
    }
    this.mockPasswordHistory.set(userId, list);
  }

  async getRecentPasswordHashes(userId: string, limit = 10): Promise<string[]> {
    const list = this.mockPasswordHistory.get(userId) ?? [];
    return list.slice(0, limit).map((e) => e.password_hash);
  }

  async markPasswordResetTokenUsed(tokenHash: string): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_RESET_PASSWORD);
    const reset = this.mockResets.get(tokenHash);
    if (reset && !reset.deleted_at) {
      reset.used = true;
    }
  }

  async saveApiKey(keyRecord: ApiKeyRecord): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_CREATE_API_KEY);
    this.mockApiKeys.set(keyRecord.key_hash, keyRecord);
  }

  async listApiKeysByOrgId(orgId: string): Promise<ApiKeyRecord[]> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_VERIFY_API_KEY);
    return [...this.mockApiKeys.values()].filter((k) => k.org_id === orgId && !k.deleted_at);
  }

  async findApiKeyByHash(hash: string): Promise<ApiKeyRecord | null> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_VERIFY_API_KEY);
    const key = this.mockApiKeys.get(hash);
    if (!key || key.deleted_at) return null;
    return key;
  }

  async revokeApiKey(keyId: string): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_REVOKE_API_KEY);
    for (const record of this.mockApiKeys.values()) {
      if (record.key_id === keyId && !record.deleted_at) {
        record.revoked = true;
      }
    }
  }

  async updateApiKeyUsage(keyId: string, lastUsedAtMs: number, lastUsedIp?: string): Promise<void> {
    for (const record of this.mockApiKeys.values()) {
      if (record.key_id === keyId && !record.deleted_at) {
        record.last_used_at_ms = lastUsedAtMs;
        record.last_used_ip = lastUsedIp ?? null;
      }
    }
  }

  async updateApiKeyAllowlist(keyId: string, ipAllowlist: readonly string[]): Promise<{ key_id: string; org_id: string; ip_allowlist: string[]; rate_quota_rpm: number | null } | null> {
    for (const record of this.mockApiKeys.values()) {
      if (record.key_id === keyId && !record.deleted_at) {
        record.ip_allowlist = [...ipAllowlist];
        return { key_id: record.key_id, org_id: record.org_id, ip_allowlist: record.ip_allowlist, rate_quota_rpm: record.rate_quota_rpm ?? null };
      }
    }
    return null;
  }

  async findApiKeyMeta(keyId: string): Promise<{ key_id: string; org_id: string; ip_allowlist: string[]; rate_quota_rpm: number | null; anomaly_flag: boolean } | null> {
    for (const record of this.mockApiKeys.values()) {
      if (record.key_id === keyId && !record.deleted_at) {
        return { key_id: record.key_id, org_id: record.org_id, ip_allowlist: record.ip_allowlist ?? [], rate_quota_rpm: record.rate_quota_rpm ?? null, anomaly_flag: record.anomaly_flag ?? false };
      }
    }
    return null;
  }

  async flagApiKeyAnomaly(keyId: string, flaggedAtMs: number): Promise<void> {
    for (const record of this.mockApiKeys.values()) {
      if (record.key_id === keyId && !record.deleted_at) {
        record.anomaly_flag = true;
        record.anomaly_flagged_at_ms = flaggedAtMs;
      }
    }
  }

  async saveEmailVerificationToken(tokenHash: string, userId: string, email: string, expiresAtMs: number): Promise<void> {
    this.mockEmailVerifications.set(tokenHash, { tokenHash, userId, email, expiresAtMs, used: false });
  }

  async findEmailVerificationToken(tokenHash: string): Promise<{ tokenHash: string; userId: string; email: string; expiresAtMs: number; used: boolean } | null> {
    const record = this.mockEmailVerifications.get(tokenHash);
    if (!record || record.deleted_at) return null;
    return record;
  }

  async markEmailVerified(tokenHash: string, userId: string): Promise<void> {
    const record = this.mockEmailVerifications.get(tokenHash);
    if (record && !record.deleted_at) {
      record.used = true;
    }
    for (const user of this.mockUsers.values()) {
      if (user.id === userId && !user.deleted_at) {
        user.email_verified = true;
      }
    }
  }

  async fetchUserAuditLogs(userId: string, filters?: { event_type?: string; from_ms?: number; to_ms?: number }): Promise<AuditLogRecord[]> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_AUDIT_LOGS);
    return [...this.mockAuditLogs.values()].filter((log) => {
      if (log.user_id !== userId || log.deleted_at) return false;
      if (filters?.event_type && log.event_type !== filters.event_type) return false;
      if (filters?.from_ms && log.timestamp_ms < filters.from_ms) return false;
      if (filters?.to_ms && log.timestamp_ms > filters.to_ms) return false;
      return true;
    });
  }

  async addTokenToDenylist(token: string, expiresAtMs: number): Promise<void> {
    this.tokenDenylist.set(token, expiresAtMs);
  }

  async isTokenDenylisted(token: string): Promise<boolean> {
    const exp = this.tokenDenylist.get(token);
    if (!exp) return false;
    if (exp < Date.now()) {
      this.tokenDenylist.delete(token);
      return false;
    }
    return true;
  }

  async setMfaSecret(userId: string, secret: string): Promise<void> {
    for (const user of this.mockUsers.values()) {
      if (user.id === userId && !user.deleted_at) {
        (user as any).mfa_secret = secret;
      }
    }
  }

  async enableMfa(userId: string, enrolledAtMs: number): Promise<void> {
    for (const user of this.mockUsers.values()) {
      if (user.id === userId && !user.deleted_at) {
        (user as any).mfa_enabled = true;
        (user as any).mfa_enrolled_at_ms = enrolledAtMs;
      }
    }
  }

  async saveRecoveryCodes(userId: string, codeHashes: string[]): Promise<void> {
    for (const hash of codeHashes) {
      const id = `rc_${Math.random().toString(36).substring(2, 15)}`;
      this.mockRecoveryCodes.set(`${userId}:${hash}`, {
        id,
        user_id: userId,
        code_hash: hash,
        used: false,
      });
    }
  }

  async findRecoveryCode(userId: string, codeHash: string): Promise<{ id: string; user_id: string; code_hash: string; used: boolean } | null> {
    const record = this.mockRecoveryCodes.get(`${userId}:${codeHash}`);
    if (!record) return null;
    return { ...record };
  }

  async consumeRecoveryCode(id: string, usedAtMs: number): Promise<void> {
    for (const record of this.mockRecoveryCodes.values()) {
      if (record.id === id) {
        record.used = true;
        (record as any).used_at_ms = usedAtMs;
      }
    }
  }

  async createRefreshTokenFamily(familyId: string, userId: string, createdAtMs: number): Promise<void> {
    this.mockRefreshFamilies.set(familyId, {
      id: familyId,
      user_id: userId,
      created_at_ms: createdAtMs,
      is_revoked: false,
    });
  }

  async findRefreshTokenFamily(familyId: string): Promise<{ id: string; user_id: string; is_revoked: boolean; revoked_reason?: string } | null> {
    const record = this.mockRefreshFamilies.get(familyId);
    if (!record) return null;
    return { ...record };
  }

  async revokeRefreshTokenFamily(familyId: string, reason: string): Promise<void> {
    const family = this.mockRefreshFamilies.get(familyId);
    if (family) {
      family.is_revoked = true;
      family.revoked_reason = reason;
    }
    for (const token of this.mockRefreshTokens.values()) {
      if (token.familyId === familyId) {
        token.isRevoked = true;
      }
    }
  }

  async saveRefreshToken(token: {
    tokenId: string;
    familyId: string;
    userId: string;
    tokenHash: string;
    generation: number;
    expiresAtMs: number;
    createdAtMs: number;
    createdIp?: string;
    userAgent?: string;
  }): Promise<void> {
    this.mockRefreshTokens.set(token.tokenHash, {
      ...token,
      isRevoked: false,
    });
  }

  async findRefreshTokenByHash(tokenHash: string): Promise<{
    tokenId: string;
    familyId: string;
    userId: string;
    tokenHash: string;
    generation: number;
    isRevoked: boolean;
    expiresAtMs: number;
    createdAtMs: number;
    consumedAtMs?: number;
  } | null> {
    const token = this.mockRefreshTokens.get(tokenHash);
    if (!token) return null;
    return { ...token };
  }

  async consumeRefreshToken(tokenId: string, consumedAtMs: number): Promise<void> {
    for (const token of this.mockRefreshTokens.values()) {
      if (token.tokenId === tokenId) {
        token.consumedAtMs = consumedAtMs;
      }
    }
  }

  async exportUserData(userId: string): Promise<{
    user: AuthUserRecord;
    organizations: OrganizationRecord[];
    apiKeys: ApiKeyRecord[];
    auditLogs: AuditLogRecord[];
  } | null> {
    const user = await this.findUserById(userId);
    if (!user) return null;

    const orgs = await this.listOrganizationsByUserId(userId);
    const apiKeys = user.org_id ? await this.listApiKeysByOrgId(user.org_id) : [];
    const auditLogs = await this.fetchUserAuditLogs(userId);

    return {
      user,
      organizations: orgs,
      apiKeys,
      auditLogs,
    };
  }

  async listActiveSessionsByUserId(userId: string): Promise<Array<{
    familyId: string;
    userId: string;
    createdAtMs: number;
    lastActiveAtMs: number;
    createdIp?: string;
    userAgent?: string;
  }>> {
    const nowMs = Date.now();
    const activeFamilies = [...this.mockRefreshFamilies.values()].filter(
      (f) => f.user_id === userId && !f.is_revoked
    );

    return activeFamilies.map((fam) => {
      const familyTokens = [...this.mockRefreshTokens.values()]
        .filter((t) => t.familyId === fam.id && !t.isRevoked && t.expiresAtMs > nowMs)
        .sort((a, b) => b.generation - a.generation);

      const latestToken = familyTokens[0];
      const lastActiveAtMs = latestToken
        ? (latestToken.consumedAtMs ?? latestToken.createdAtMs)
        : fam.created_at_ms;

      return {
        familyId: fam.id,
        userId: fam.user_id,
        createdAtMs: fam.created_at_ms,
        lastActiveAtMs,
        createdIp: latestToken?.createdIp,
        userAgent: latestToken?.userAgent,
      };
    });
  }

  async revokeOtherSessionsByUserId(userId: string, currentFamilyId: string, reason: string): Promise<number> {
    let count = 0;
    for (const fam of this.mockRefreshFamilies.values()) {
      if (fam.user_id === userId && fam.id !== currentFamilyId && !fam.is_revoked) {
        fam.is_revoked = true;
        fam.revoked_reason = reason;
        count += 1;
      }
    }

    for (const tok of this.mockRefreshTokens.values()) {
      if (tok.userId === userId && tok.familyId !== currentFamilyId && !tok.isRevoked) {
        tok.isRevoked = true;
      }
    }

    return count;
  }

  private readonly mockFederatedIdentities = new Map<string, FederatedIdentityRecord>();

  async findFederatedIdentity(provider: string, providerSubjectId: string): Promise<FederatedIdentityRecord | null> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_FEDERATED_IDENTITY);
    for (const identity of this.mockFederatedIdentities.values()) {
      if (identity.provider === provider && identity.provider_subject_id === providerSubjectId) {
        return { ...identity };
      }
    }
    return null;
  }

  async findFederatedIdentityByUserAndProvider(userId: string, provider: string): Promise<FederatedIdentityRecord | null> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_FEDERATED_IDENTITY);
    for (const identity of this.mockFederatedIdentities.values()) {
      if (identity.user_id === userId && identity.provider === provider) {
        return { ...identity };
      }
    }
    return null;
  }

  async listFederatedIdentitiesByUserId(userId: string): Promise<FederatedIdentityRecord[]> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_FEDERATED_IDENTITY);
    return [...this.mockFederatedIdentities.values()]
      .filter((i) => i.user_id === userId)
      .map((i) => ({ ...i }));
  }

  async saveFederatedIdentity(identity: FederatedIdentityRecord): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_FEDERATED_IDENTITY);
    this.mockFederatedIdentities.set(identity.id, { ...identity });
  }

  async deleteFederatedIdentity(userId: string, provider: string): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_FEDERATED_IDENTITY);
    for (const [id, identity] of this.mockFederatedIdentities.entries()) {
      if (identity.user_id === userId && identity.provider === provider) {
        this.mockFederatedIdentities.delete(id);
      }
    }
  }

  async countFederatedIdentitiesByUserId(userId: string): Promise<number> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_FEDERATED_IDENTITY);
    return [...this.mockFederatedIdentities.values()].filter((i) => i.user_id === userId).length;
  }

  async saveClaimedDomain(domainRecord: ClaimedDomainRecord): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_DOMAIN_CLAIM);
    this.mockClaimedDomains.set(domainRecord.id, { ...domainRecord });
  }

  async findClaimedDomainById(domainId: string): Promise<ClaimedDomainRecord | null> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_DOMAIN_CLAIM);
    const domain = this.mockClaimedDomains.get(domainId);
    if (!domain || domain.deleted_at) return null;
    return { ...domain };
  }

  async findClaimedDomainByName(domainName: string): Promise<ClaimedDomainRecord | null> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_DOMAIN_CLAIM);
    for (const d of this.mockClaimedDomains.values()) {
      if (d.domain_name.toLowerCase() === domainName.toLowerCase() && !d.deleted_at) {
        return { ...d };
      }
    }
    return null;
  }

  async listClaimedDomainsByOrgId(orgId: string): Promise<ClaimedDomainRecord[]> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_DOMAIN_CLAIM);
    return [...this.mockClaimedDomains.values()]
      .filter((d) => d.org_id === orgId && !d.deleted_at)
      .map((d) => ({ ...d }));
  }

  async updateClaimedDomainStatus(domainId: string, status: string, verifiedAtMs?: number): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_DOMAIN_CLAIM);
    const domain = this.mockClaimedDomains.get(domainId);
    if (domain) {
      domain.status = status as any;
      if (verifiedAtMs) domain.verified_at_ms = verifiedAtMs;
      domain.last_checked_at_ms = Date.now();
    }
  }

  async updateClaimedDomainSettings(domainId: string, autoJoinEnabled: boolean, defaultRole: string): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_DOMAIN_CLAIM);
    const domain = this.mockClaimedDomains.get(domainId);
    if (domain) {
      domain.auto_join_enabled = autoJoinEnabled;
      domain.default_role = defaultRole;
    }
  }

  async deleteClaimedDomain(domainId: string): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_DOMAIN_CLAIM);
    const domain = this.mockClaimedDomains.get(domainId);
    if (domain) {
      domain.deleted_at = Date.now();
    }
  }

  async listPendingOrVerifiedDomains(): Promise<ClaimedDomainRecord[]> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_DOMAIN_CLAIM);
    return [...this.mockClaimedDomains.values()]
      .filter((d) => !d.deleted_at && (d.status === AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_PENDING || d.status === AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_VERIFIED))
      .map((d) => ({ ...d }));
  }

  private readonly mockBlockedDomains = new Map<string, BlockedDomainRecord>();

  async findBlockedDomain(domainName: string): Promise<BlockedDomainRecord | null> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_BLOCKED_DOMAINS);
    const item = this.mockBlockedDomains.get(domainName.toLowerCase());
    return item ? { ...item } : null;
  }

  async listBlockedDomains(): Promise<BlockedDomainRecord[]> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_BLOCKED_DOMAINS);
    return [...this.mockBlockedDomains.values()].map((d) => ({ ...d }));
  }

  async saveBlockedDomain(record: BlockedDomainRecord): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_BLOCKED_DOMAINS);
    this.mockBlockedDomains.set(record.domain_name.toLowerCase(), { ...record });
  }

  async deleteBlockedDomain(domainName: string): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_BLOCKED_DOMAINS);
    this.mockBlockedDomains.delete(domainName.toLowerCase());
  }

  private readonly mockLoginHistory = new Map<string, Array<{
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
  }>>();

  async recordLoginHistory(record: {
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
  }): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_LOGIN_HISTORY);
    const userHistory = this.mockLoginHistory.get(record.userId) || [];
    userHistory.unshift({ ...record });
    this.mockLoginHistory.set(record.userId, userHistory);
  }

  async getLatestLoginLocation(userId: string): Promise<{
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
  } | null> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_LOGIN_HISTORY);
    const userHistory = this.mockLoginHistory.get(userId);
    if (!userHistory || userHistory.length === 0) {
      return null;
    }
    return { ...userHistory[0]! };
  }

  private readonly mockRelationTuples = new Map<string, RelationTuple>();

  async saveRelationTuple(tuple: RelationTuple): Promise<void> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_RELATION_TUPLES);
    const key = `${tuple.org_id}:${tuple.subject_type}:${tuple.subject_id}:${tuple.relation}:${tuple.object_type}:${tuple.object_id}`;
    this.mockRelationTuples.set(key, { ...tuple });
  }

  async deleteRelationTuple(
    orgId: string,
    subjectType: string,
    subjectId: string,
    relation: string,
    objectType: string,
    objectId: string,
  ): Promise<boolean> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_RELATION_TUPLES);
    const key = `${orgId}:${subjectType}:${subjectId}:${relation}:${objectType}:${objectId}`;
    const existing = this.mockRelationTuples.get(key);
    if (!existing || existing.deleted_at_ms) return false;
    existing.status = 'REVOKED';
    existing.deleted_at_ms = Date.now();
    return true;
  }

  async findRelationTuples(
    orgId: string,
    filter?: {
      subject_type?: string;
      subject_id?: string;
      relation?: string;
      object_type?: string;
      object_id?: string;
    },
  ): Promise<RelationTuple[]> {
    this.getFlowQuery(AUTH_CONSTANTS.AUTH_QUERY_FLOWS.FLOW_RELATION_TUPLES);
    const now = Date.now();
    let results = [...this.mockRelationTuples.values()].filter(
      (t) => t.org_id === orgId && !t.deleted_at_ms && t.status === 'ACTIVE' && (!t.expires_at_ms || t.expires_at_ms > now)
    );
    if (filter?.subject_type) {
      results = results.filter((t) => t.subject_type === filter.subject_type);
    }
    if (filter?.subject_id) {
      results = results.filter((t) => t.subject_id === filter.subject_id);
    }
    if (filter?.relation) {
      results = results.filter((t) => t.relation === filter.relation);
    }
    if (filter?.object_type) {
      results = results.filter((t) => t.object_type === filter.object_type);
    }
    if (filter?.object_id) {
      results = results.filter((t) => t.object_id === filter.object_id);
    }
    return results.map((t) => ({ ...t }));
  }

  private readonly mockScimTokens = new Map<string, { id: string; org_id: string; token_hash: string; description: string; status: 'ACTIVE' | 'REVOKED'; created_at_ms: number; expires_at_ms: number | null; last_used_at_ms: number | null }>();
  private readonly mockScimMappings = new Map<string, string>();
  private readonly mockScimGroups = new Map<string, { id: string; org_id: string; displayName: string; externalId?: string; created_at_ms: number; updated_at_ms: number }>();
  private readonly mockGroupMembers = new Map<string, Set<string>>();

  async saveScimToken(record: { id: string; org_id: string; token_hash: string; description: string; status: 'ACTIVE' | 'REVOKED'; created_at_ms: number; expires_at_ms: number | null; last_used_at_ms: number | null }): Promise<void> {
    this.mockScimTokens.set(record.token_hash, { ...record });
  }

  async findScimTokenByHash(tokenHash: string): Promise<{ id: string; org_id: string; token_hash: string; description: string; status: 'ACTIVE' | 'REVOKED'; created_at_ms: number; expires_at_ms: number | null; last_used_at_ms: number | null } | null> {
    const token = this.mockScimTokens.get(tokenHash);
    return token ? { ...token } : null;
  }

  async saveExternalMapping(orgId: string, resourceType: 'user' | 'group', internalId: string, externalId: string): Promise<void> {
    const key = `${orgId}:${resourceType}:${externalId}`;
    this.mockScimMappings.set(key, internalId);
  }

  async findExternalMapping(orgId: string, resourceType: 'user' | 'group', externalId: string): Promise<string | null> {
    const key = `${orgId}:${resourceType}:${externalId}`;
    return this.mockScimMappings.get(key) || null;
  }

  async saveScimGroup(orgId: string, group: { id: string; displayName: string; externalId?: string }): Promise<void> {
    const now = Date.now();
    this.mockScimGroups.set(group.id, {
      id: group.id,
      org_id: orgId,
      displayName: group.displayName,
      externalId: group.externalId,
      created_at_ms: now,
      updated_at_ms: now,
    });
  }

  async findScimGroupById(orgId: string, groupId: string): Promise<{ id: string; externalId?: string; displayName: string; members: ReadonlyArray<{ value: string; display?: string }>; meta: { resourceType: 'Group'; created: string; lastModified: string; location: string } } | null> {
    const g = this.mockScimGroups.get(groupId);
    if (!g || g.org_id !== orgId) {
      return null;
    }
    const memberIds = [...(this.mockGroupMembers.get(groupId) || new Set())];
    const members = memberIds.map((userId) => {
      const u = [...this.mockUsers.values()].find((usr) => usr.id === userId);
      return { value: userId, display: u?.name || u?.email || userId };
    });
    return {
      id: g.id,
      externalId: g.externalId,
      displayName: g.displayName,
      members,
      meta: {
        resourceType: 'Group',
        created: new Date(g.created_at_ms).toISOString(),
        lastModified: new Date(g.updated_at_ms).toISOString(),
        location: `/scim/v2/Groups/${g.id}`,
      },
    };
  }

  async listScimGroups(orgId: string, _filter?: string, _startIndex?: number, _count?: number): Promise<{ groups: ReadonlyArray<{ id: string; externalId?: string; displayName: string; members: ReadonlyArray<{ value: string; display?: string }>; meta: { resourceType: 'Group'; created: string; lastModified: string; location: string } }>; total: number }> {
    const matching = [...this.mockScimGroups.values()].filter((g) => g.org_id === orgId);
    const groups = await Promise.all(matching.map((g) => this.findScimGroupById(orgId, g.id)));
    const nonNull = groups.filter((g): g is NonNullable<typeof g> => g !== null);
    return { groups: nonNull, total: nonNull.length };
  }

  async deleteScimGroup(orgId: string, groupId: string): Promise<void> {
    const g = this.mockScimGroups.get(groupId);
    if (g && g.org_id === orgId) {
      this.mockScimGroups.delete(groupId);
      this.mockGroupMembers.delete(groupId);
    }
  }

  async addScimGroupMember(groupId: string, userId: string): Promise<void> {
    if (!this.mockGroupMembers.has(groupId)) {
      this.mockGroupMembers.set(groupId, new Set());
    }
    this.mockGroupMembers.get(groupId)!.add(userId);
  }

  async removeScimGroupMember(groupId: string, userId: string): Promise<void> {
    const set = this.mockGroupMembers.get(groupId);
    if (set) {
      set.delete(userId);
    }
  }

  async listScimGroupMembers(groupId: string): Promise<ReadonlyArray<{ value: string; display?: string }>> {
    const memberIds = [...(this.mockGroupMembers.get(groupId) || new Set())];
    return memberIds.map((userId) => {
      const u = [...this.mockUsers.values()].find((usr) => usr.id === userId);
      return { value: userId, display: u?.name || u?.email || userId };
    });
  }

  private readonly mockOAuthClients = new Map<string, { id: string; org_id: string; client_name: string; client_secret_hash?: string; redirect_uris: ReadonlyArray<string>; grant_types: ReadonlyArray<string>; response_types: ReadonlyArray<string>; client_type: 'public' | 'confidential'; status: 'ACTIVE' | 'SUSPENDED'; created_at_ms: number }>();
  private readonly mockAuthCodes = new Map<string, { code: string; client_id: string; user_id: string; org_id: string; redirect_uri: string; code_challenge: string; code_challenge_method: 'S256'; scope: string; used: boolean; expires_at_ms: number; created_at_ms: number }>();
  private readonly mockSigningKeys = new Map<string, { kid: string; kty: string; alg: string; use: string; public_key_pem: string; private_key_pem: string; status: 'ACTIVE' | 'RETIRED'; created_at_ms: number }>();

  async saveOAuthClient(client: { id: string; org_id: string; client_name: string; client_secret_hash?: string; redirect_uris: ReadonlyArray<string>; grant_types: ReadonlyArray<string>; response_types: ReadonlyArray<string>; client_type: 'public' | 'confidential'; status: 'ACTIVE' | 'SUSPENDED'; created_at_ms: number }): Promise<void> {
    this.mockOAuthClients.set(client.id, { ...client });
  }

  async findOAuthClientById(clientId: string): Promise<{ id: string; org_id: string; client_name: string; client_secret_hash?: string; redirect_uris: ReadonlyArray<string>; grant_types: ReadonlyArray<string>; response_types: ReadonlyArray<string>; client_type: 'public' | 'confidential'; status: 'ACTIVE' | 'SUSPENDED'; created_at_ms: number } | null> {
    const client = this.mockOAuthClients.get(clientId);
    return client ? { ...client } : null;
  }

  async saveAuthorizationCode(codeRecord: { code: string; client_id: string; user_id: string; org_id: string; redirect_uri: string; code_challenge: string; code_challenge_method: 'S256'; scope: string; used: boolean; expires_at_ms: number; created_at_ms: number }): Promise<void> {
    this.mockAuthCodes.set(codeRecord.code, { ...codeRecord });
  }

  async findAuthorizationCode(code: string): Promise<{ code: string; client_id: string; user_id: string; org_id: string; redirect_uri: string; code_challenge: string; code_challenge_method: 'S256'; scope: string; used: boolean; expires_at_ms: number; created_at_ms: number } | null> {
    const record = this.mockAuthCodes.get(code);
    return record ? { ...record } : null;
  }

  async consumeAuthorizationCode(code: string): Promise<void> {
    const record = this.mockAuthCodes.get(code);
    if (record) {
      this.mockAuthCodes.set(code, { ...record, used: true });
    }
  }

  async saveSigningKey(key: { kid: string; kty: string; alg: string; use: string; public_key_pem: string; private_key_pem: string; status: 'ACTIVE' | 'RETIRED'; created_at_ms: number }): Promise<void> {
    this.mockSigningKeys.set(key.kid, { ...key });
  }

  async getActiveSigningKey(): Promise<{ kid: string; kty: string; alg: string; use: string; public_key_pem: string; private_key_pem: string; status: 'ACTIVE' | 'RETIRED'; created_at_ms: number } | null> {
    const active = [...this.mockSigningKeys.values()].find((k) => k.status === 'ACTIVE');
    return active ? { ...active } : null;
  }

  async saveSamlProvider(provider: any): Promise<void> {
    this.mockSamlProviders.set(provider.id, { ...provider });
  }

  async findSamlProviderByOrgId(orgId: string): Promise<any | null> {
    const p = [...this.mockSamlProviders.values()].find((item) => item.org_id === orgId && !item.deleted_at);
    return p ? { ...p } : null;
  }

  async findSamlProviderById(id: string): Promise<any | null> {
    const p = this.mockSamlProviders.get(id);
    return (p && !p.deleted_at) ? { ...p } : null;
  }

  async listSamlProviders(orgId: string): Promise<ReadonlyArray<any>> {
    return [...this.mockSamlProviders.values()].filter((item) => item.org_id === orgId && !item.deleted_at);
  }

  async saveSamlRequest(request: any): Promise<void> {
    this.mockSamlRequests.set(request.relay_state, { ...request });
  }

  async consumeSamlRequest(relayState: string): Promise<any | null> {
    const req = this.mockSamlRequests.get(relayState);
    if (!req) return null;
    this.mockSamlRequests.delete(relayState);
    return { ...req };
  }

  async recordAssertionId(assertionId: string, expiresAtMs: number): Promise<boolean> {
    if (this.mockSamlAssertionReplay.has(assertionId)) {
      return false;
    }
    this.mockSamlAssertionReplay.set(assertionId, expiresAtMs);
    return true;
  }
}






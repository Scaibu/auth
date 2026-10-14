import type { AuthRepositoryPort, OrganizationRecord } from '../../../features/auth/repository';
import type { AuthUserRecord, AuditLogRecord } from '../../../features/auth/types';
import type { ApiKeyRecord } from '../../../shared/types/auth.types';
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
  }

  public getFlowQuery(flow: keyof typeof AUTH_QUERIES): string {
    return JSON.stringify(this.queries[flow]);
  }

  async createOrganization(org: OrganizationRecord, creatorUserId?: string): Promise<void> {
    this.getFlowQuery('FLOW_CREATE_ORGANIZATION');
    const existing = [...this.mockOrgs.values()].find((o) => !o.deleted_at && o.name.toLowerCase() === org.name.toLowerCase());
    if (existing) {
      throw new Error(`Organization name already exists: ${org.name}`);
    }
    this.mockOrgs.set(org.id, { ...org });
    if (creatorUserId) {
      if (!this.mockUserOrgs.has(creatorUserId)) this.mockUserOrgs.set(creatorUserId, new Set());
      this.mockUserOrgs.get(creatorUserId)!.add(org.id);
    }
  }

  async listOrganizationsByUserId(userId: string): Promise<OrganizationRecord[]> {
    this.getFlowQuery('FLOW_CREATE_ORGANIZATION');
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
    this.getFlowQuery('FLOW_CREATE_ORGANIZATION');
    const org = this.mockOrgs.get(orgId);
    if (!org || org.deleted_at) return null;
    return org;
  }

  async updateOrganization(orgId: string, patch: { name?: string; slug?: string }): Promise<void> {
    this.getFlowQuery('FLOW_CREATE_ORGANIZATION');
    const org = this.mockOrgs.get(orgId);
    if (org && !org.deleted_at) {
      if (patch.name) org.name = patch.name;
      if (patch.slug) org.slug = patch.slug;
    }
  }

  async deleteOrganization(orgId: string): Promise<void> {
    this.getFlowQuery('FLOW_DELETE_ORGANIZATION');
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
    this.getFlowQuery('FLOW_CREATE_USER');
    const existing = [...this.mockUsers.values()].find((u) => !u.deleted_at && u.email === userRecord.email);
    if (existing) {
      throw new Error(`User with email ${userRecord.email} already exists`);
    }
    this.mockUsers.set(userRecord.email, { ...userRecord });
    if (!this.mockUserOrgs.has(userRecord.id)) this.mockUserOrgs.set(userRecord.id, new Set());
    this.mockUserOrgs.get(userRecord.id)!.add(userRecord.org_id);
  }

  async listUsersByOrgId(orgId: string): Promise<AuthUserRecord[]> {
    this.getFlowQuery('FLOW_CREATE_USER');
    return [...this.mockUsers.values()].filter((u) => u.org_id === orgId && !u.deleted_at);
  }

  async blockUser(userId: string): Promise<void> {
    this.getFlowQuery('FLOW_BLOCK_USER');
    for (const user of this.mockUsers.values()) {
      if (user.id === userId && !user.deleted_at) {
        user.blocked = true;
      }
    }
  }

  async unblockUser(userId: string): Promise<void> {
    this.getFlowQuery('FLOW_BLOCK_USER');
    for (const user of this.mockUsers.values()) {
      if (user.id === userId && !user.deleted_at) {
        user.blocked = false;
      }
    }
  }

  async deleteUser(userId: string): Promise<void> {
    this.getFlowQuery('FLOW_DELETE_USER');
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
    this.getFlowQuery('FLOW_RETENTION_PURGE');
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
    this.getFlowQuery('FLOW_SIGN_IN');
    const user = this.mockUsers.get(email);
    if (!user || user.deleted_at) return null;
    return user;
  }

  async findUserById(id: string): Promise<AuthUserRecord | null> {
    this.getFlowQuery('FLOW_SESSION_VERIFY');
    const user = [...this.mockUsers.values()].find((u) => u.id === id && !u.deleted_at);
    return user ?? null;
  }

  async createOrganizationAndUser(userRecord: AuthUserRecord): Promise<void> {
    this.getFlowQuery('FLOW_SIGN_UP');
    const existingOrg = [...this.mockOrgs.values()].find((o) => !o.deleted_at && o.name.toLowerCase() === userRecord.org_name.toLowerCase());
    if (existingOrg) {
      throw new Error(`Organization name already exists: ${userRecord.org_name}`);
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
    this.getFlowQuery('FLOW_SIGN_IN');
    this.mockAuditLogs.set(logRecord.id, logRecord);
  }

  async savePasswordResetToken(tokenHash: string, userId: string, expiresAtMs: number): Promise<void> {
    this.getFlowQuery('FLOW_FORGOT_PASSWORD');
    this.mockResets.set(tokenHash, { tokenHash, userId, expiresAtMs, used: false });
  }

  async findPasswordResetToken(tokenHash: string): Promise<{ tokenHash: string; userId: string; expiresAtMs: number; used: boolean } | null> {
    this.getFlowQuery('FLOW_FORGOT_PASSWORD');
    const reset = this.mockResets.get(tokenHash);
    if (!reset || reset.deleted_at) return null;
    return reset;
  }

  async updateUserPassword(userId: string, newPasswordHash: string): Promise<void> {
    this.getFlowQuery('FLOW_RESET_PASSWORD');
    for (const user of this.mockUsers.values()) {
      if (user.id === userId && !user.deleted_at) {
        user.password_hash = newPasswordHash;
      }
    }
  }

  async markPasswordResetTokenUsed(tokenHash: string): Promise<void> {
    this.getFlowQuery('FLOW_RESET_PASSWORD');
    const reset = this.mockResets.get(tokenHash);
    if (reset && !reset.deleted_at) {
      reset.used = true;
    }
  }

  async saveApiKey(keyRecord: ApiKeyRecord): Promise<void> {
    this.getFlowQuery('FLOW_CREATE_API_KEY');
    this.mockApiKeys.set(keyRecord.key_hash, keyRecord);
  }

  async listApiKeysByOrgId(orgId: string): Promise<ApiKeyRecord[]> {
    this.getFlowQuery('FLOW_VERIFY_API_KEY');
    return [...this.mockApiKeys.values()].filter((k) => k.org_id === orgId && !k.deleted_at);
  }

  async findApiKeyByHash(hash: string): Promise<ApiKeyRecord | null> {
    this.getFlowQuery('FLOW_VERIFY_API_KEY');
    const key = this.mockApiKeys.get(hash);
    if (!key || key.deleted_at) return null;
    return key;
  }

  async revokeApiKey(keyId: string): Promise<void> {
    this.getFlowQuery('FLOW_REVOKE_API_KEY');
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
    this.getFlowQuery('FLOW_AUDIT_LOGS');
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
}

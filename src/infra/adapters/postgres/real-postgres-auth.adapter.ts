import { Pool } from 'pg';
import { SpanKind } from '@chief-strategist-j/shared-infra';
import { AUTH_CONFIG } from '../../../config/env.config';
import type { AuthRepositoryPort, OrganizationRecord } from '../../../features/auth/repository';
import type { AuthUserRecord, AuditLogRecord } from '../../../features/auth/types';
import type { ApiKeyRecord, FederatedIdentityRecord, ClaimedDomainRecord, BlockedDomainRecord, RelationTuple } from '../../../shared/types/auth.types';
import { REAL_POSTGRES_QUERIES, AUTH_QUERIES } from './queries/real-postgres.queries';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { withSpan } from '../../tracing/tracer';

export class RealPostgresAuthAdapter implements AuthRepositoryPort {
  private readonly pool: Pool;
  public readonly queries = REAL_POSTGRES_QUERIES;

  constructor(connectionString?: string) {
    this.pool = new Pool({
      connectionString: connectionString ?? AUTH_CONFIG.db.url,
      host: AUTH_CONFIG.db.host,
      port: AUTH_CONFIG.db.port,
      user: AUTH_CONFIG.db.user,
      password: AUTH_CONFIG.db.password,
      database: AUTH_CONFIG.db.name,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });
    this.pool.on('connect', (client: any) => {
      client.on('error', (err: any) => {
        if (err?.code !== '57P01' && !err?.message?.includes('terminating connection')) {
          console.error('[PostgreSQL Client Error]', err);
        }
      });
    });
    this.pool.on('error', (err: any) => {
      if (err?.code !== '57P01' && !err?.message?.includes('terminating connection')) {
        console.error('[PostgreSQL Pool Error]', err);
      }
    });
  }

  public async getPoolStatus(): Promise<{ totalCount: number; idleCount: number; waitingCount: number }> {
    return {
      totalCount: this.pool.totalCount,
      idleCount: this.pool.idleCount,
      waitingCount: this.pool.waitingCount,
    };
  }

  public async close(): Promise<void> {
    await this.pool.end();
  }

  private async setTenantRlsContext(client: any, orgId: string): Promise<void> {
    await client.query(AUTH_QUERIES.TENANT_RLS.SET_LOCAL_TENANT_CONTEXT, [orgId]);
  }

  async createOrganization(org: OrganizationRecord, creatorUserId?: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const check = await client.query(AUTH_QUERIES.FLOW_CREATE_ORGANIZATION.CHECK_ORG_NAME, [org.name]);
      if (check.rows.length > 0) {
        throw new Error(`Organization name already exists: ${org.name}`);
      }
      await client.query(AUTH_QUERIES.FLOW_CREATE_ORGANIZATION.INSERT_ORG, [org.id, org.name, org.slug]);
      if (creatorUserId) {
        await client.query(AUTH_QUERIES.FLOW_CREATE_ORGANIZATION.INSERT_USER_ORG, [creatorUserId, org.id, AUTH_CONSTANTS.ROLE_ADMIN]);
      }
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async listOrganizationsByUserId(userId: string): Promise<OrganizationRecord[]> {
    const client = await this.pool.connect();
    try {
      const res = await client.query(AUTH_QUERIES.FLOW_CREATE_ORGANIZATION.LIST_BY_USER, [userId]);
      return res.rows.map((row: any) => ({ id: row.id, name: row.name, slug: row.slug }));
    } finally {
      client.release();
    }
  }

  async getOrganizationById(orgId: string): Promise<OrganizationRecord | null> {
    const client = await this.pool.connect();
    try {
      const res = await client.query(AUTH_QUERIES.FLOW_CREATE_ORGANIZATION.GET_BY_ID, [orgId]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return { id: row.id, name: row.name, slug: row.slug };
    } finally {
      client.release();
    }
  }

  async updateOrganization(orgId: string, patch: { name?: string; slug?: string }): Promise<void> {
    const client = await this.pool.connect();
    try {
      if (patch.name) await client.query(AUTH_QUERIES.FLOW_CREATE_ORGANIZATION.UPDATE_NAME, [patch.name, orgId]);
      if (patch.slug) await client.query(AUTH_QUERIES.FLOW_CREATE_ORGANIZATION.UPDATE_SLUG, [patch.slug, orgId]);
    } finally {
      client.release();
    }
  }

  async deleteOrganization(orgId: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(AUTH_QUERIES.FLOW_DELETE_ORGANIZATION.SOFT_DELETE_ORG, [orgId]);
      await client.query(AUTH_QUERIES.FLOW_DELETE_ORGANIZATION.CASCADE_SOFT_DELETE_USERS, [orgId]);
      await client.query(AUTH_QUERIES.FLOW_DELETE_ORGANIZATION.CASCADE_SOFT_DELETE_KEYS, [orgId]);
      await client.query(AUTH_QUERIES.FLOW_DELETE_ORGANIZATION.CASCADE_SOFT_DELETE_LOGS, [orgId]);
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async createUser(userRecord: AuthUserRecord): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const orgCheck = await client.query(AUTH_QUERIES.FLOW_CREATE_USER.FIND_ORG_BY_ID, [userRecord.org_id]);
      if (orgCheck.rows.length === 0) {
        throw new Error(`Organization ${userRecord.org_id} does not exist or has been deleted`);
      }
      const orgName = orgCheck.rows[0].name;
      await this.setTenantRlsContext(client, userRecord.org_id);
      await client.query(AUTH_QUERIES.FLOW_CREATE_USER.INSERT_USER, [
        userRecord.id,
        userRecord.email,
        userRecord.password_hash,
        userRecord.name,
        userRecord.org_id,
        orgName,
        userRecord.role ?? AUTH_CONSTANTS.ROLE_MEMBER,
        userRecord.user_permissions ?? [],
      ]);
      await client.query(AUTH_QUERIES.FLOW_CREATE_USER.INSERT_USER_ORG, [userRecord.id, userRecord.org_id, userRecord.role ?? AUTH_CONSTANTS.ROLE_MEMBER]);
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async listUsersByOrgId(orgId: string): Promise<AuthUserRecord[]> {
    const client = await this.pool.connect();
    try {
      const res = await client.query(AUTH_QUERIES.FLOW_CREATE_USER.LIST_BY_ORG, [orgId]);
      return res.rows.map((row: any) => ({
        id: row.id,
        email: row.email,
        password_hash: row.password_hash,
        name: row.name,
        org_id: row.org_id,
        org_name: row.org_name,
        role: row.role,
        blocked: row.blocked,
        user_permissions: row.user_permissions ?? [],
        email_verified: row.email_verified ?? false,
      }));
    } finally {
      client.release();
    }
  }

  async blockUser(userId: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_QUERIES.FLOW_BLOCK_USER.BLOCK_USER, [userId]);
    } finally {
      client.release();
    }
  }

  async unblockUser(userId: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_QUERIES.FLOW_CREATE_USER.UNBLOCK_USER, [userId]);
    } finally {
      client.release();
    }
  }

  async deleteUser(userId: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_QUERIES.FLOW_DELETE_USER.SOFT_DELETE_USER, [userId]);
    } finally {
      client.release();
    }
  }

  async updateUserProfile(userId: string, patch: { name?: string }): Promise<void> {
    const client = await this.pool.connect();
    try {
      if (patch.name) await client.query(AUTH_QUERIES.FLOW_CREATE_USER.UPDATE_PROFILE_NAME, [patch.name, userId]);
    } finally {
      client.release();
    }
  }

  async updateUserRole(userId: string, role: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_QUERIES.FLOW_CREATE_USER.UPDATE_ROLE, [role, userId]);
    } finally {
      client.release();
    }
  }

  async updateUserPermissions(userId: string, permissions: string[]): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_QUERIES.FLOW_CREATE_USER.UPDATE_PERMISSIONS, [permissions, userId]);
    } finally {
      client.release();
    }
  }

  async purgeExpiredSoftDeletes(): Promise<number> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const r1 = await client.query(AUTH_QUERIES.FLOW_RETENTION_PURGE.PURGE_ORGS);
      const r2 = await client.query(AUTH_QUERIES.FLOW_RETENTION_PURGE.PURGE_USERS);
      const r3 = await client.query(AUTH_QUERIES.FLOW_RETENTION_PURGE.PURGE_KEYS);
      const r4 = await client.query(AUTH_QUERIES.FLOW_RETENTION_PURGE.PURGE_LOGS);
      const r5 = await client.query(AUTH_QUERIES.FLOW_RETENTION_PURGE.PURGE_RESETS);
      const r6 = await client.query(AUTH_QUERIES.FLOW_RETENTION_PURGE.PURGE_DENYLIST, [Date.now()]);
      const r7 = await client.query(AUTH_QUERIES.FLOW_RETENTION_PURGE.PURGE_REFRESH_TOKENS);
      await client.query('COMMIT');
      return (r1.rowCount ?? 0) + (r2.rowCount ?? 0) + (r3.rowCount ?? 0) + (r4.rowCount ?? 0) + (r5.rowCount ?? 0) + (r6.rowCount ?? 0) + (r7.rowCount ?? 0);
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async findUserByEmail(email: string): Promise<AuthUserRecord | null> {
    return withSpan('DB SELECT findUserByEmail', async (span) => {
      span.setAttribute('db.system', 'postgresql');
      span.setAttribute('db.operation', 'SELECT');
      span.setAttribute('db.sql.table', 'users');
      const client = await this.pool.connect();
      try {
        const res = await client.query(AUTH_QUERIES.FLOW_SIGN_IN.FIND_USER_BY_EMAIL, [email]);
        if (res.rows.length === 0) return null;
        const row = res.rows[0];
        return {
          id: row.id,
          email: row.email,
          password_hash: row.password_hash,
          name: row.name,
          org_id: row.org_id,
          org_name: row.org_name,
          role: row.role,
          blocked: row.blocked,
          user_permissions: row.user_permissions ?? [],
          email_verified: row.email_verified ?? false,
        };
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async findUserById(id: string): Promise<AuthUserRecord | null> {
    const client = await this.pool.connect();
    try {
      const res = await client.query(AUTH_QUERIES.FLOW_SESSION_VERIFY.FIND_USER_BY_ID, [id]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        id: row.id,
        email: row.email,
        password_hash: row.password_hash,
        name: row.name,
        org_id: row.org_id,
        org_name: row.org_name,
        role: row.role,
        blocked: row.blocked,
        user_permissions: row.user_permissions ?? [],
        email_verified: row.email_verified ?? false,
      };
    } finally {
      client.release();
    }
  }

  async createOrganizationAndUser(userRecord: AuthUserRecord): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const orgCheck = await client.query(AUTH_QUERIES.FLOW_SIGN_UP.CHECK_ORG_EXISTS, [userRecord.org_name, userRecord.org_name.toLowerCase()]);
      if (orgCheck.rows.length > 0) {
        throw new Error(`Organization name already exists: ${userRecord.org_name}`);
      }

      await client.query(AUTH_QUERIES.FLOW_SIGN_UP.INSERT_ORG, [userRecord.org_id, userRecord.org_name, userRecord.org_name.toLowerCase()]);
      await this.setTenantRlsContext(client, userRecord.org_id);
      await client.query(AUTH_QUERIES.FLOW_SIGN_UP.INSERT_USER, [
        userRecord.id,
        userRecord.email,
        userRecord.password_hash,
        userRecord.name,
        userRecord.org_id,
        userRecord.org_name,
        userRecord.role ?? AUTH_CONSTANTS.ROLE_ADMIN,
        userRecord.user_permissions ?? [],
      ]);
      await client.query(AUTH_QUERIES.FLOW_SIGN_UP.INSERT_USER_ORG, [userRecord.id, userRecord.org_id, userRecord.role ?? AUTH_CONSTANTS.ROLE_ADMIN]);
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async recordAuditLog(logRecord: AuditLogRecord): Promise<void> {
    return withSpan('DB INSERT recordAuditLog', async (span) => {
      span.setAttribute('db.system', 'postgresql');
      span.setAttribute('db.operation', 'INSERT');
      span.setAttribute('db.sql.table', 'audit_logs');
      const client = await this.pool.connect();
      try {
        await this.setTenantRlsContext(client, logRecord.org_id);
        await client.query(AUTH_QUERIES.FLOW_SIGN_IN.RECORD_AUDIT_LOG, [
          logRecord.id,
          logRecord.user_id,
          logRecord.org_id,
          logRecord.event_type,
          logRecord.ip_address,
          logRecord.user_agent,
          logRecord.timestamp_ms,
        ]);
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async savePasswordResetToken(tokenHash: string, userId: string, expiresAtMs: number): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_QUERIES.FLOW_FORGOT_PASSWORD.INSERT_RESET_TOKEN, [tokenHash, userId, expiresAtMs, false]);
    } finally {
      client.release();
    }
  }

  async findPasswordResetToken(tokenHash: string): Promise<{ tokenHash: string; userId: string; expiresAtMs: number; used: boolean } | null> {
    const client = await this.pool.connect();
    try {
      const res = await client.query(AUTH_QUERIES.FLOW_FORGOT_PASSWORD.FIND_RESET_TOKEN, [tokenHash]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        tokenHash: row.token_hash,
        userId: row.user_id,
        expiresAtMs: parseInt(row.expires_at_ms, 10),
        used: row.used,
      };
    } finally {
      client.release();
    }
  }

  async updateUserPassword(userId: string, newPasswordHash: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_QUERIES.FLOW_RESET_PASSWORD.UPDATE_PASSWORD_HASH, [newPasswordHash, userId]);
    } finally {
      client.release();
    }
  }

  async markPasswordResetTokenUsed(tokenHash: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_QUERIES.FLOW_RESET_PASSWORD.MARK_TOKEN_USED, [tokenHash]);
    } finally {
      client.release();
    }
  }

  async saveApiKey(keyRecord: ApiKeyRecord): Promise<void> {
    const client = await this.pool.connect();
    try {
      await this.setTenantRlsContext(client, keyRecord.org_id);
      await client.query(AUTH_QUERIES.FLOW_CREATE_API_KEY.INSERT_API_KEY, [
        keyRecord.key_id,
        keyRecord.org_id,
        keyRecord.key_type,
        keyRecord.key_hash,
        keyRecord.prefix,
        keyRecord.name,
        keyRecord.permissions,
        keyRecord.created_at_ms,
        keyRecord.revoked,
        keyRecord.expires_at_ms ?? null,
      ]);
    } finally {
      client.release();
    }
  }

  async listApiKeysByOrgId(orgId: string): Promise<ApiKeyRecord[]> {
    const client = await this.pool.connect();
    try {
      const res = await client.query(AUTH_QUERIES.FLOW_CREATE_API_KEY.LIST_BY_ORG, [orgId]);
      return res.rows.map((row: any) => ({
        key_id: row.key_id,
        org_id: row.org_id,
        key_type: row.key_type,
        key_hash: row.key_hash,
        prefix: row.prefix,
        name: row.name,
        permissions: row.permissions,
        created_at_ms: parseInt(row.created_at_ms, 10),
        revoked: row.revoked,
        expires_at_ms: row.expires_at_ms ? parseInt(row.expires_at_ms, 10) : null,
        last_used_at_ms: row.last_used_at_ms ? parseInt(row.last_used_at_ms, 10) : null,
        last_used_ip: row.last_used_ip ?? null,
      }));
    } finally {
      client.release();
    }
  }

  async findApiKeyByHash(hash: string): Promise<ApiKeyRecord | null> {
    const client = await this.pool.connect();
    try {
      const res = await client.query(AUTH_QUERIES.FLOW_VERIFY_API_KEY.FIND_API_KEY_BY_HASH, [hash]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        key_id: row.key_id,
        org_id: row.org_id,
        key_type: row.key_type,
        key_hash: row.key_hash,
        prefix: row.prefix,
        name: row.name,
        permissions: row.permissions,
        created_at_ms: parseInt(row.created_at_ms, 10),
        revoked: row.revoked,
        expires_at_ms: row.expires_at_ms ? parseInt(row.expires_at_ms, 10) : null,
        last_used_at_ms: row.last_used_at_ms ? parseInt(row.last_used_at_ms, 10) : null,
        last_used_ip: row.last_used_ip ?? null,
      };
    } finally {
      client.release();
    }
  }

  async revokeApiKey(keyId: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_QUERIES.FLOW_REVOKE_API_KEY.REVOKE_API_KEY_BY_ID, [keyId]);
    } finally {
      client.release();
    }
  }

  async updateApiKeyUsage(keyId: string, lastUsedAtMs: number, lastUsedIp?: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_QUERIES.FLOW_API_KEY_USAGE.UPDATE_USAGE, [lastUsedAtMs, lastUsedIp ?? null, keyId]);
    } finally {
      client.release();
    }
  }

  async saveEmailVerificationToken(tokenHash: string, userId: string, email: string, expiresAtMs: number): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_QUERIES.FLOW_EMAIL_VERIFICATION.INSERT_TOKEN, [tokenHash, userId, email, expiresAtMs, false]);
    } finally {
      client.release();
    }
  }

  async findEmailVerificationToken(tokenHash: string): Promise<{ tokenHash: string; userId: string; email: string; expiresAtMs: number; used: boolean } | null> {
    const client = await this.pool.connect();
    try {
      const res = await client.query(AUTH_QUERIES.FLOW_EMAIL_VERIFICATION.FIND_TOKEN, [tokenHash]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        tokenHash: row.token_hash,
        userId: row.user_id,
        email: row.email,
        expiresAtMs: parseInt(row.expires_at_ms, 10),
        used: row.used,
      };
    } finally {
      client.release();
    }
  }

  async markEmailVerified(tokenHash: string, userId: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(AUTH_QUERIES.FLOW_EMAIL_VERIFICATION.MARK_VERIFIED, [tokenHash]);
      await client.query(AUTH_QUERIES.FLOW_EMAIL_VERIFICATION.SET_USER_EMAIL_VERIFIED, [userId]);
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async fetchUserAuditLogs(userId: string, filters?: { event_type?: string; from_ms?: number; to_ms?: number }): Promise<AuditLogRecord[]> {
    const client = await this.pool.connect();
    try {
      const res = await client.query(AUTH_QUERIES.FLOW_AUDIT_LOGS.FETCH_LOGS_BY_USER_FILTERED, [
        userId,
        filters?.event_type ?? null,
        filters?.from_ms ?? null,
        filters?.to_ms ?? null,
      ]);
      return res.rows.map((row: any) => ({
        id: row.id,
        user_id: row.user_id,
        org_id: row.org_id,
        event_type: row.event_type,
        ip_address: row.ip_address,
        user_agent: row.user_agent,
        timestamp_ms: parseInt(row.timestamp_ms, 10),
      }));
    } finally {
      client.release();
    }
  }

  async addTokenToDenylist(token: string, expiresAtMs: number): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_QUERIES.FLOW_SESSION_VERIFY.ADD_TOKEN_DENYLIST, [token, expiresAtMs]);
    } finally {
      client.release();
    }
  }

  async isTokenDenylisted(token: string): Promise<boolean> {
    const client = await this.pool.connect();
    try {
      const res = await client.query(AUTH_QUERIES.FLOW_SESSION_VERIFY.CHECK_TOKEN_DENYLIST, [token, Date.now()]);
      return res.rows.length > 0;
    } finally {
      client.release();
    }
  }

  async setMfaSecret(userId: string, secret: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_QUERIES.FLOW_MFA.SET_SECRET, [secret, userId]);
    } finally {
      client.release();
    }
  }

  async enableMfa(userId: string, enrolledAtMs: number): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_QUERIES.FLOW_MFA.ENABLE_MFA, [enrolledAtMs, userId]);
    } finally {
      client.release();
    }
  }

  async saveRecoveryCodes(userId: string, codeHashes: string[]): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const now = Date.now();
      for (const hash of codeHashes) {
        const id = `rc_${Math.random().toString(36).substring(2, 15)}`;
        await client.query(AUTH_QUERIES.FLOW_MFA.INSERT_RECOVERY_CODE, [id, userId, hash, now]);
      }
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async findRecoveryCode(userId: string, codeHash: string): Promise<{ id: string; user_id: string; code_hash: string; used: boolean } | null> {
    const client = await this.pool.connect();
    try {
      const res = await client.query(AUTH_QUERIES.FLOW_MFA.FIND_RECOVERY_CODE, [userId, codeHash]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        id: row.id,
        user_id: row.user_id,
        code_hash: row.code_hash,
        used: row.used,
      };
    } finally {
      client.release();
    }
  }

  async consumeRecoveryCode(id: string, usedAtMs: number): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_QUERIES.FLOW_MFA.CONSUME_RECOVERY_CODE, [usedAtMs, id]);
    } finally {
      client.release();
    }
  }

  async createRefreshTokenFamily(familyId: string, userId: string, createdAtMs: number): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_QUERIES.FLOW_REFRESH_TOKEN.INSERT_FAMILY, [familyId, userId, createdAtMs]);
    } finally {
      client.release();
    }
  }

  async findRefreshTokenFamily(familyId: string): Promise<{ id: string; user_id: string; is_revoked: boolean; revoked_reason?: string } | null> {
    const client = await this.pool.connect();
    try {
      const res = await client.query(AUTH_QUERIES.FLOW_REFRESH_TOKEN.FIND_FAMILY, [familyId]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        id: row.id,
        user_id: row.user_id,
        is_revoked: row.is_revoked,
        revoked_reason: row.revoked_reason,
      };
    } finally {
      client.release();
    }
  }

  async revokeRefreshTokenFamily(familyId: string, reason: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(AUTH_QUERIES.FLOW_REFRESH_TOKEN.REVOKE_FAMILY, [reason, familyId]);
      await client.query(AUTH_QUERIES.FLOW_REFRESH_TOKEN.REVOKE_TOKEN_FAMILY_TOKENS, [familyId]);
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
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
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_QUERIES.FLOW_REFRESH_TOKEN.INSERT_TOKEN, [
        token.tokenId,
        token.familyId,
        token.userId,
        token.tokenHash,
        token.generation,
        token.expiresAtMs,
        token.createdAtMs,
        token.createdIp ?? null,
        token.userAgent ?? null,
      ]);
    } finally {
      client.release();
    }
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
    const client = await this.pool.connect();
    try {
      const res = await client.query(AUTH_QUERIES.FLOW_REFRESH_TOKEN.FIND_TOKEN_BY_HASH, [tokenHash]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        tokenId: row.token_id,
        familyId: row.family_id,
        userId: row.user_id,
        tokenHash: row.token_hash,
        generation: row.generation,
        isRevoked: row.is_revoked,
        expiresAtMs: Number(row.expires_at_ms),
        createdAtMs: Number(row.created_at_ms),
        consumedAtMs: row.consumed_at_ms ? Number(row.consumed_at_ms) : undefined,
      };
    } finally {
      client.release();
    }
  }

  async consumeRefreshToken(tokenId: string, consumedAtMs: number): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_QUERIES.FLOW_REFRESH_TOKEN.CONSUME_TOKEN, [consumedAtMs, tokenId]);
    } finally {
      client.release();
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
    const client = await this.pool.connect();
    try {
      const nowMs = Date.now();
      const res = await client.query(AUTH_QUERIES.FLOW_REFRESH_TOKEN.LIST_ACTIVE_FAMILIES, [userId, nowMs]);
      return res.rows.map((row: any) => ({
        familyId: row.family_id,
        userId: row.user_id,
        createdAtMs: Number(row.created_at_ms),
        lastActiveAtMs: Number(row.last_active_at_ms),
        createdIp: row.created_ip ?? undefined,
        userAgent: row.user_agent ?? undefined,
      }));
    } finally {
      client.release();
    }
  }

  async revokeOtherSessionsByUserId(userId: string, currentFamilyId: string, reason: string): Promise<number> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_CONSTANTS.TRANSACTION.BEGIN);
      const res = await client.query(AUTH_QUERIES.FLOW_REFRESH_TOKEN.REVOKE_OTHER_FAMILIES, [reason, userId, currentFamilyId]);
      await client.query(AUTH_QUERIES.FLOW_REFRESH_TOKEN.REVOKE_OTHER_TOKENS, [userId, currentFamilyId]);
      await client.query(AUTH_CONSTANTS.TRANSACTION.COMMIT);
      return res.rowCount ?? 0;
    } catch (err: unknown) {
      await client.query(AUTH_CONSTANTS.TRANSACTION.ROLLBACK);
      throw err;
    } finally {
      client.release();
    }
  }

  async findFederatedIdentity(provider: string, providerSubjectId: string): Promise<FederatedIdentityRecord | null> {
    return withSpan('db.findFederatedIdentity', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      const res = await this.pool.query(AUTH_QUERIES.FLOW_FEDERATED_IDENTITY.FIND_BY_PROVIDER_SUBJECT, [provider, providerSubjectId]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        id: row.id,
        user_id: row.user_id,
        provider: row.provider,
        provider_subject_id: row.provider_subject_id,
        email: row.email,
        created_at_ms: Number(row.created_at_ms),
        updated_at_ms: Number(row.updated_at_ms),
      };
    }, { kind: SpanKind.CLIENT });
  }

  async findFederatedIdentityByUserAndProvider(userId: string, provider: string): Promise<FederatedIdentityRecord | null> {
    return withSpan('db.findFederatedIdentityByUserAndProvider', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      const res = await this.pool.query(AUTH_QUERIES.FLOW_FEDERATED_IDENTITY.FIND_BY_USER_AND_PROVIDER, [userId, provider]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        id: row.id,
        user_id: row.user_id,
        provider: row.provider,
        provider_subject_id: row.provider_subject_id,
        email: row.email,
        created_at_ms: Number(row.created_at_ms),
        updated_at_ms: Number(row.updated_at_ms),
      };
    }, { kind: SpanKind.CLIENT });
  }

  async listFederatedIdentitiesByUserId(userId: string): Promise<FederatedIdentityRecord[]> {
    return withSpan('db.listFederatedIdentitiesByUserId', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      const res = await this.pool.query(AUTH_QUERIES.FLOW_FEDERATED_IDENTITY.LIST_BY_USER_ID, [userId]);
      return res.rows.map((row) => ({
        id: row.id,
        user_id: row.user_id,
        provider: row.provider,
        provider_subject_id: row.provider_subject_id,
        email: row.email,
        created_at_ms: Number(row.created_at_ms),
        updated_at_ms: Number(row.updated_at_ms),
      }));
    }, { kind: SpanKind.CLIENT });
  }

  async saveFederatedIdentity(identity: FederatedIdentityRecord): Promise<void> {
    await withSpan('db.saveFederatedIdentity', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      await this.pool.query(AUTH_QUERIES.FLOW_FEDERATED_IDENTITY.INSERT_IDENTITY, [
        identity.id,
        identity.user_id,
        identity.provider,
        identity.provider_subject_id,
        identity.email,
        identity.created_at_ms,
        identity.updated_at_ms,
      ]);
    }, { kind: SpanKind.CLIENT });
  }

  async deleteFederatedIdentity(userId: string, provider: string): Promise<void> {
    await withSpan('db.deleteFederatedIdentity', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      await this.pool.query(AUTH_QUERIES.FLOW_FEDERATED_IDENTITY.DELETE_IDENTITY, [userId, provider]);
    }, { kind: SpanKind.CLIENT });
  }

  async countFederatedIdentitiesByUserId(userId: string): Promise<number> {
    return withSpan('db.countFederatedIdentitiesByUserId', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      const res = await this.pool.query(AUTH_QUERIES.FLOW_FEDERATED_IDENTITY.COUNT_BY_USER_ID, [userId]);
      return Number(res.rows[0]?.count ?? 0);
    }, { kind: SpanKind.CLIENT });
  }

  async saveClaimedDomain(domainRecord: ClaimedDomainRecord): Promise<void> {
    await withSpan('db.saveClaimedDomain', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      await this.pool.query(AUTH_QUERIES.FLOW_DOMAIN_CLAIM.INSERT_DOMAIN, [
        domainRecord.id,
        domainRecord.org_id,
        domainRecord.domain_name,
        domainRecord.status,
        domainRecord.verification_token,
        domainRecord.verification_method,
        domainRecord.default_role,
        domainRecord.auto_join_enabled,
        domainRecord.created_at_ms,
      ]);
    }, { kind: SpanKind.CLIENT });
  }

  async findClaimedDomainById(domainId: string): Promise<ClaimedDomainRecord | null> {
    return withSpan('db.findClaimedDomainById', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      const res = await this.pool.query(AUTH_QUERIES.FLOW_DOMAIN_CLAIM.FIND_BY_ID, [domainId]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        id: row.id,
        org_id: row.org_id,
        domain_name: row.domain_name,
        status: row.status,
        verification_token: row.verification_token,
        verification_method: row.verification_method,
        default_role: row.default_role,
        auto_join_enabled: Boolean(row.auto_join_enabled),
        created_at_ms: Number(row.created_at_ms),
        verified_at_ms: row.verified_at_ms ? Number(row.verified_at_ms) : null,
        last_checked_at_ms: row.last_checked_at_ms ? Number(row.last_checked_at_ms) : null,
      };
    }, { kind: SpanKind.CLIENT });
  }

  async findClaimedDomainByName(domainName: string): Promise<ClaimedDomainRecord | null> {
    return withSpan('db.findClaimedDomainByName', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      const res = await this.pool.query(AUTH_QUERIES.FLOW_DOMAIN_CLAIM.FIND_BY_NAME, [domainName]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        id: row.id,
        org_id: row.org_id,
        domain_name: row.domain_name,
        status: row.status,
        verification_token: row.verification_token,
        verification_method: row.verification_method,
        default_role: row.default_role,
        auto_join_enabled: Boolean(row.auto_join_enabled),
        created_at_ms: Number(row.created_at_ms),
        verified_at_ms: row.verified_at_ms ? Number(row.verified_at_ms) : null,
        last_checked_at_ms: row.last_checked_at_ms ? Number(row.last_checked_at_ms) : null,
      };
    }, { kind: SpanKind.CLIENT });
  }

  async listClaimedDomainsByOrgId(orgId: string): Promise<ClaimedDomainRecord[]> {
    return withSpan('db.listClaimedDomainsByOrgId', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      const res = await this.pool.query(AUTH_QUERIES.FLOW_DOMAIN_CLAIM.LIST_BY_ORG_ID, [orgId]);
      return res.rows.map((row: any) => ({
        id: row.id,
        org_id: row.org_id,
        domain_name: row.domain_name,
        status: row.status,
        verification_token: row.verification_token,
        verification_method: row.verification_method,
        default_role: row.default_role,
        auto_join_enabled: Boolean(row.auto_join_enabled),
        created_at_ms: Number(row.created_at_ms),
        verified_at_ms: row.verified_at_ms ? Number(row.verified_at_ms) : null,
        last_checked_at_ms: row.last_checked_at_ms ? Number(row.last_checked_at_ms) : null,
      }));
    }, { kind: SpanKind.CLIENT });
  }

  async updateClaimedDomainStatus(domainId: string, status: string, verifiedAtMs?: number): Promise<void> {
    await withSpan('db.updateClaimedDomainStatus', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      const now = Date.now();
      await this.pool.query(AUTH_QUERIES.FLOW_DOMAIN_CLAIM.UPDATE_STATUS, [status, verifiedAtMs ?? null, now, domainId]);
    }, { kind: SpanKind.CLIENT });
  }

  async updateClaimedDomainSettings(domainId: string, autoJoinEnabled: boolean, defaultRole: string): Promise<void> {
    await withSpan('db.updateClaimedDomainSettings', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      await this.pool.query(AUTH_QUERIES.FLOW_DOMAIN_CLAIM.UPDATE_SETTINGS, [autoJoinEnabled, defaultRole, domainId]);
    }, { kind: SpanKind.CLIENT });
  }

  async deleteClaimedDomain(domainId: string): Promise<void> {
    await withSpan('db.deleteClaimedDomain', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      await this.pool.query(AUTH_QUERIES.FLOW_DOMAIN_CLAIM.SOFT_DELETE, [domainId]);
    }, { kind: SpanKind.CLIENT });
  }

  async listPendingOrVerifiedDomains(): Promise<ClaimedDomainRecord[]> {
    return withSpan('db.listPendingOrVerifiedDomains', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      const res = await this.pool.query(AUTH_QUERIES.FLOW_DOMAIN_CLAIM.LIST_PENDING_OR_VERIFIED);
      return res.rows.map((row: any) => ({
        id: row.id,
        org_id: row.org_id,
        domain_name: row.domain_name,
        status: row.status,
        verification_token: row.verification_token,
        verification_method: row.verification_method,
        default_role: row.default_role,
        auto_join_enabled: Boolean(row.auto_join_enabled),
        created_at_ms: Number(row.created_at_ms),
        verified_at_ms: row.verified_at_ms ? Number(row.verified_at_ms) : null,
        last_checked_at_ms: row.last_checked_at_ms ? Number(row.last_checked_at_ms) : null,
      }));
    }, { kind: SpanKind.CLIENT });
  }

  async findBlockedDomain(domainName: string): Promise<BlockedDomainRecord | null> {
    return withSpan('db.findBlockedDomain', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      const res = await this.pool.query(AUTH_QUERIES.FLOW_BLOCKED_DOMAINS.FIND_BY_NAME, [domainName.toLowerCase()]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        domain_name: row.domain_name,
        category: row.category,
        reason: row.reason,
        created_at_ms: Number(row.created_at_ms),
        updated_at_ms: Number(row.updated_at_ms),
      };
    }, { kind: SpanKind.CLIENT });
  }

  async listBlockedDomains(): Promise<BlockedDomainRecord[]> {
    return withSpan('db.listBlockedDomains', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      const res = await this.pool.query(AUTH_QUERIES.FLOW_BLOCKED_DOMAINS.LIST_ALL);
      return res.rows.map((row: any) => ({
        domain_name: row.domain_name,
        category: row.category,
        reason: row.reason,
        created_at_ms: Number(row.created_at_ms),
        updated_at_ms: Number(row.updated_at_ms),
      }));
    }, { kind: SpanKind.CLIENT });
  }

  async saveBlockedDomain(record: BlockedDomainRecord): Promise<void> {
    await withSpan('db.saveBlockedDomain', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      await this.pool.query(AUTH_QUERIES.FLOW_BLOCKED_DOMAINS.INSERT, [
        record.domain_name.toLowerCase(),
        record.category,
        record.reason ?? null,
        record.created_at_ms,
        record.updated_at_ms,
      ]);
    }, { kind: SpanKind.CLIENT });
  }

  async deleteBlockedDomain(domainName: string): Promise<void> {
    await withSpan('db.deleteBlockedDomain', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      await this.pool.query(AUTH_QUERIES.FLOW_BLOCKED_DOMAINS.DELETE, [domainName.toLowerCase()]);
    }, { kind: SpanKind.CLIENT });
  }

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
    await withSpan('db.recordLoginHistory', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      await this.pool.query(AUTH_QUERIES.FLOW_LOGIN_HISTORY.INSERT, [
        record.id,
        record.userId,
        record.ipAddress,
        record.latitude ?? null,
        record.longitude ?? null,
        record.asn ?? null,
        record.isDatacenter,
        record.deviceFingerprint,
        record.riskScore,
        record.createdAtMs,
      ]);
    }, { kind: SpanKind.CLIENT });
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
    return withSpan('db.getLatestLoginLocation', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      const res = await this.pool.query(AUTH_QUERIES.FLOW_LOGIN_HISTORY.FIND_LATEST_BY_USER, [userId]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        id: row.id,
        userId: row.user_id,
        ipAddress: row.ip_address,
        latitude: row.latitude !== null ? Number(row.latitude) : undefined,
        longitude: row.longitude !== null ? Number(row.longitude) : undefined,
        asn: row.asn ?? undefined,
        isDatacenter: Boolean(row.is_datacenter),
        deviceFingerprint: row.device_fingerprint,
        riskScore: Number(row.risk_score),
        createdAtMs: Number(row.created_at_ms),
      };
    }, { kind: SpanKind.CLIENT });
  }

  async saveRelationTuple(tuple: RelationTuple): Promise<void> {
    return withSpan('db.saveRelationTuple', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      span.setAttribute('tenant.org_id', tuple.org_id);
      await this.pool.query(AUTH_QUERIES.FLOW_RELATION_TUPLES.INSERT, [
        tuple.id,
        tuple.org_id,
        tuple.subject_type,
        tuple.subject_id,
        tuple.relation,
        tuple.object_type,
        tuple.object_id,
        JSON.stringify(tuple.conditions || {}),
        tuple.status || 'ACTIVE',
        tuple.expires_at_ms ?? null,
        tuple.granted_by ?? null,
        tuple.version ?? 1,
        tuple.created_at_ms,
      ]);
    }, { kind: SpanKind.CLIENT });
  }

  async deleteRelationTuple(
    orgId: string,
    subjectType: string,
    subjectId: string,
    relation: string,
    objectType: string,
    objectId: string,
  ): Promise<boolean> {
    return withSpan('db.deleteRelationTuple', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      span.setAttribute('tenant.org_id', orgId);
      const res = await this.pool.query(AUTH_QUERIES.FLOW_RELATION_TUPLES.DELETE, [
        orgId,
        subjectType,
        subjectId,
        relation,
        objectType,
        objectId,
      ]);
      return (res.rowCount ?? 0) > 0;
    }, { kind: SpanKind.CLIENT });
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
    return withSpan('db.findRelationTuples', async (span) => {
      span.setAttribute(AUTH_CONSTANTS.SPAN_DB_SYSTEM, AUTH_CONSTANTS.SPAN_DB_SYSTEM_VAL);
      span.setAttribute('tenant.org_id', orgId);

      const now = Date.now();
      const conditions = [
        'org_id = $1',
        'deleted_at IS NULL',
        "status = 'ACTIVE'",
        '(expires_at_ms IS NULL OR expires_at_ms > $2)',
      ];
      const values: unknown[] = [orgId, now];
      let paramIdx = 3;

      if (filter?.subject_type) {
        conditions.push(`subject_type = $${paramIdx++}`);
        values.push(filter.subject_type);
      }
      if (filter?.subject_id) {
        conditions.push(`subject_id = $${paramIdx++}`);
        values.push(filter.subject_id);
      }
      if (filter?.relation) {
        conditions.push(`relation = $${paramIdx++}`);
        values.push(filter.relation);
      }
      if (filter?.object_type) {
        conditions.push(`object_type = $${paramIdx++}`);
        values.push(filter.object_type);
      }
      if (filter?.object_id) {
        conditions.push(`object_id = $${paramIdx++}`);
        values.push(filter.object_id);
      }

      const sql = `SELECT id, org_id, subject_type, subject_id, relation, object_type, object_id, conditions, status, expires_at_ms, granted_by, version, created_at_ms FROM auth_relation_tuples WHERE ${conditions.join(' AND ')} ORDER BY created_at_ms ASC`;
      const res = await this.pool.query(sql, values);
      return res.rows.map((row) => ({
        id: row.id,
        org_id: row.org_id,
        subject_type: row.subject_type,
        subject_id: row.subject_id,
        relation: row.relation,
        object_type: row.object_type,
        object_id: row.object_id,
        conditions: typeof row.conditions === 'string' ? JSON.parse(row.conditions) : (row.conditions || {}),
        status: row.status,
        expires_at_ms: row.expires_at_ms !== null ? Number(row.expires_at_ms) : undefined,
        granted_by: row.granted_by ?? undefined,
        version: Number(row.version),
        created_at_ms: Number(row.created_at_ms),
      }));
    }, { kind: SpanKind.CLIENT });
  }

  async saveScimToken(record: { id: string; org_id: string; token_hash: string; description: string; status: 'ACTIVE' | 'REVOKED'; created_at_ms: number; expires_at_ms: number | null; last_used_at_ms: number | null }): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.saveScimToken', async () => {
      const sql = `INSERT INTO auth_scim_tokens (id, org_id, token_hash, description, status, created_at_ms, expires_at_ms, last_used_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`;
      await this.pool.query(sql, [record.id, record.org_id, record.token_hash, record.description, record.status, record.created_at_ms, record.expires_at_ms, record.last_used_at_ms]);
    }, { kind: SpanKind.CLIENT });
  }

  async findScimTokenByHash(tokenHash: string): Promise<{ id: string; org_id: string; token_hash: string; description: string; status: 'ACTIVE' | 'REVOKED'; created_at_ms: number; expires_at_ms: number | null; last_used_at_ms: number | null } | null> {
    return withSpan('RealPostgresAuthAdapter.findScimTokenByHash', async () => {
      const sql = `SELECT id, org_id, token_hash, description, status, created_at_ms, expires_at_ms, last_used_at_ms FROM auth_scim_tokens WHERE token_hash = $1 AND deleted_at IS NULL AND status = 'ACTIVE'`;
      const res = await this.pool.query(sql, [tokenHash]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        id: row.id,
        org_id: row.org_id,
        token_hash: row.token_hash,
        description: row.description,
        status: row.status,
        created_at_ms: Number(row.created_at_ms),
        expires_at_ms: row.expires_at_ms !== null ? Number(row.expires_at_ms) : null,
        last_used_at_ms: row.last_used_at_ms !== null ? Number(row.last_used_at_ms) : null,
      };
    }, { kind: SpanKind.CLIENT });
  }

  async saveExternalMapping(orgId: string, resourceType: 'user' | 'group', internalId: string, externalId: string): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.saveExternalMapping', async () => {
      const now = Date.now();
      const sql = `INSERT INTO auth_scim_external_mappings (id, org_id, resource_type, internal_id, external_id, created_at_ms, updated_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (org_id, resource_type, external_id) DO UPDATE SET internal_id = $4, updated_at_ms = $7`;
      const id = `map_${now}_${Math.random().toString(36).substring(2, 9)}`;
      await this.pool.query(sql, [id, orgId, resourceType, internalId, externalId, now, now]);
    }, { kind: SpanKind.CLIENT });
  }

  async findExternalMapping(orgId: string, resourceType: 'user' | 'group', externalId: string): Promise<string | null> {
    return withSpan('RealPostgresAuthAdapter.findExternalMapping', async () => {
      const sql = `SELECT internal_id FROM auth_scim_external_mappings WHERE org_id = $1 AND resource_type = $2 AND external_id = $3`;
      const res = await this.pool.query(sql, [orgId, resourceType, externalId]);
      return res.rows.length > 0 ? res.rows[0].internal_id : null;
    }, { kind: SpanKind.CLIENT });
  }

  async saveScimGroup(orgId: string, group: { id: string; displayName: string; externalId?: string }): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.saveScimGroup', async () => {
      const now = Date.now();
      const sql = `INSERT INTO auth_groups (id, org_id, display_name, created_at_ms, updated_at_ms) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO UPDATE SET display_name = $3, updated_at_ms = $5`;
      await this.pool.query(sql, [group.id, orgId, group.displayName, now, now]);
      if (group.externalId) {
        await this.saveExternalMapping(orgId, 'group', group.id, group.externalId);
      }
    }, { kind: SpanKind.CLIENT });
  }

  async findScimGroupById(orgId: string, groupId: string): Promise<{ id: string; externalId?: string; displayName: string; members: ReadonlyArray<{ value: string; display?: string }>; meta: { resourceType: 'Group'; created: string; lastModified: string; location: string } } | null> {
    return withSpan('RealPostgresAuthAdapter.findScimGroupById', async () => {
      const groupSql = `SELECT g.id, g.display_name, g.created_at_ms, g.updated_at_ms, m.external_id FROM auth_groups g LEFT JOIN auth_scim_external_mappings m ON m.internal_id = g.id AND m.resource_type = 'group' WHERE g.id = $1 AND g.org_id = $2 AND g.deleted_at IS NULL`;
      const res = await this.pool.query(groupSql, [groupId, orgId]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];

      const membersSql = `SELECT gm.user_id, u.name, u.email FROM auth_group_members gm JOIN auth_users u ON u.id = gm.user_id WHERE gm.group_id = $1`;
      const memRes = await this.pool.query(membersSql, [groupId]);
      const members = memRes.rows.map((m: any) => ({
        value: m.user_id,
        display: m.name || m.email || m.user_id,
      }));

      return {
        id: row.id,
        externalId: row.external_id ?? undefined,
        displayName: row.display_name,
        members,
        meta: {
          resourceType: 'Group',
          created: new Date(Number(row.created_at_ms)).toISOString(),
          lastModified: new Date(Number(row.updated_at_ms)).toISOString(),
          location: `/scim/v2/Groups/${row.id}`,
        },
      };
    }, { kind: SpanKind.CLIENT });
  }

  async listScimGroups(orgId: string, _filter?: string, _startIndex?: number, _count?: number): Promise<{ groups: ReadonlyArray<{ id: string; externalId?: string; displayName: string; members: ReadonlyArray<{ value: string; display?: string }>; meta: { resourceType: 'Group'; created: string; lastModified: string; location: string } }>; total: number }> {
    return withSpan('RealPostgresAuthAdapter.listScimGroups', async () => {
      const sql = `SELECT id FROM auth_groups WHERE org_id = $1 AND deleted_at IS NULL ORDER BY created_at_ms ASC`;
      const res = await this.pool.query(sql, [orgId]);
      const groups = await Promise.all(res.rows.map((r: any) => this.findScimGroupById(orgId, r.id)));
      const nonNull = groups.filter((g): g is NonNullable<typeof g> => g !== null);
      return { groups: nonNull, total: nonNull.length };
    }, { kind: SpanKind.CLIENT });
  }

  async deleteScimGroup(orgId: string, groupId: string): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.deleteScimGroup', async () => {
      const sql = `UPDATE auth_groups SET deleted_at = CURRENT_TIMESTAMP WHERE id = $1 AND org_id = $2`;
      await this.pool.query(sql, [groupId, orgId]);
    }, { kind: SpanKind.CLIENT });
  }

  async addScimGroupMember(groupId: string, userId: string): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.addScimGroupMember', async () => {
      const now = Date.now();
      const id = `gm_${now}_${Math.random().toString(36).substring(2, 9)}`;
      const sql = `INSERT INTO auth_group_members (id, group_id, user_id, added_at_ms) VALUES ($1, $2, $3, $4) ON CONFLICT (group_id, user_id) DO NOTHING`;
      await this.pool.query(sql, [id, groupId, userId, now]);
    }, { kind: SpanKind.CLIENT });
  }

  async removeScimGroupMember(groupId: string, userId: string): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.removeScimGroupMember', async () => {
      const sql = `DELETE FROM auth_group_members WHERE group_id = $1 AND user_id = $2`;
      await this.pool.query(sql, [groupId, userId]);
    }, { kind: SpanKind.CLIENT });
  }

  async listScimGroupMembers(groupId: string): Promise<ReadonlyArray<{ value: string; display?: string }>> {
    return withSpan('RealPostgresAuthAdapter.listScimGroupMembers', async () => {
      const sql = `SELECT gm.user_id, u.name, u.email FROM auth_group_members gm JOIN auth_users u ON u.id = gm.user_id WHERE gm.group_id = $1`;
      const res = await this.pool.query(sql, [groupId]);
      return res.rows.map((m: any) => ({
        value: m.user_id,
        display: m.name || m.email || m.user_id,
      }));
    }, { kind: SpanKind.CLIENT });
  }

  async saveOAuthClient(client: { id: string; org_id: string; client_name: string; client_secret_hash?: string; redirect_uris: ReadonlyArray<string>; grant_types: ReadonlyArray<string>; response_types: ReadonlyArray<string>; client_type: 'public' | 'confidential'; status: 'ACTIVE' | 'SUSPENDED'; created_at_ms: number }): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.saveOAuthClient', async () => {
      const sql = `INSERT INTO auth_oauth_clients (id, org_id, client_name, client_secret_hash, redirect_uris, grant_types, response_types, client_type, status, created_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (id) DO UPDATE SET client_name = $3, redirect_uris = $5, status = $9`;
      await this.pool.query(sql, [
        client.id,
        client.org_id,
        client.client_name,
        client.client_secret_hash ?? null,
        JSON.stringify(client.redirect_uris),
        JSON.stringify(client.grant_types),
        JSON.stringify(client.response_types),
        client.client_type,
        client.status,
        client.created_at_ms,
      ]);
    }, { kind: SpanKind.CLIENT });
  }

  async findOAuthClientById(clientId: string): Promise<{ id: string; org_id: string; client_name: string; client_secret_hash?: string; redirect_uris: ReadonlyArray<string>; grant_types: ReadonlyArray<string>; response_types: ReadonlyArray<string>; client_type: 'public' | 'confidential'; status: 'ACTIVE' | 'SUSPENDED'; created_at_ms: number } | null> {
    return withSpan('RealPostgresAuthAdapter.findOAuthClientById', async () => {
      const sql = `SELECT id, org_id, client_name, client_secret_hash, redirect_uris, grant_types, response_types, client_type, status, created_at_ms FROM auth_oauth_clients WHERE id = $1 AND deleted_at IS NULL AND status = 'ACTIVE'`;
      const res = await this.pool.query(sql, [clientId]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        id: row.id,
        org_id: row.org_id,
        client_name: row.client_name,
        client_secret_hash: row.client_secret_hash ?? undefined,
        redirect_uris: typeof row.redirect_uris === 'string' ? JSON.parse(row.redirect_uris) : (row.redirect_uris || []),
        grant_types: typeof row.grant_types === 'string' ? JSON.parse(row.grant_types) : (row.grant_types || []),
        response_types: typeof row.response_types === 'string' ? JSON.parse(row.response_types) : (row.response_types || []),
        client_type: row.client_type,
        status: row.status,
        created_at_ms: Number(row.created_at_ms),
      };
    }, { kind: SpanKind.CLIENT });
  }

  async saveAuthorizationCode(codeRecord: { code: string; client_id: string; user_id: string; org_id: string; redirect_uri: string; code_challenge: string; code_challenge_method: 'S256'; scope: string; used: boolean; expires_at_ms: number; created_at_ms: number }): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.saveAuthorizationCode', async () => {
      const sql = `INSERT INTO auth_oauth_codes (code, client_id, user_id, org_id, redirect_uri, code_challenge, code_challenge_method, scope, used, expires_at_ms, created_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`;
      await this.pool.query(sql, [
        codeRecord.code,
        codeRecord.client_id,
        codeRecord.user_id,
        codeRecord.org_id,
        codeRecord.redirect_uri,
        codeRecord.code_challenge,
        codeRecord.code_challenge_method,
        codeRecord.scope,
        codeRecord.used,
        codeRecord.expires_at_ms,
        codeRecord.created_at_ms,
      ]);
    }, { kind: SpanKind.CLIENT });
  }

  async findAuthorizationCode(code: string): Promise<{ code: string; client_id: string; user_id: string; org_id: string; redirect_uri: string; code_challenge: string; code_challenge_method: 'S256'; scope: string; used: boolean; expires_at_ms: number; created_at_ms: number } | null> {
    return withSpan('RealPostgresAuthAdapter.findAuthorizationCode', async () => {
      const sql = `SELECT code, client_id, user_id, org_id, redirect_uri, code_challenge, code_challenge_method, scope, used, expires_at_ms, created_at_ms FROM auth_oauth_codes WHERE code = $1`;
      const res = await this.pool.query(sql, [code]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        code: row.code,
        client_id: row.client_id,
        user_id: row.user_id,
        org_id: row.org_id,
        redirect_uri: row.redirect_uri,
        code_challenge: row.code_challenge,
        code_challenge_method: row.code_challenge_method,
        scope: row.scope,
        used: Boolean(row.used),
        expires_at_ms: Number(row.expires_at_ms),
        created_at_ms: Number(row.created_at_ms),
      };
    }, { kind: SpanKind.CLIENT });
  }

  async consumeAuthorizationCode(code: string): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.consumeAuthorizationCode', async () => {
      const sql = `UPDATE auth_oauth_codes SET used = TRUE WHERE code = $1`;
      await this.pool.query(sql, [code]);
    }, { kind: SpanKind.CLIENT });
  }

  async saveSigningKey(key: { kid: string; kty: string; alg: string; use: string; public_key_pem: string; private_key_pem: string; status: 'ACTIVE' | 'RETIRED'; created_at_ms: number }): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.saveSigningKey', async () => {
      const sql = `INSERT INTO auth_signing_keys (kid, kty, alg, use, public_key_pem, private_key_pem, status, created_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (kid) DO NOTHING`;
      await this.pool.query(sql, [key.kid, key.kty, key.alg, key.use, key.public_key_pem, key.private_key_pem, key.status, key.created_at_ms]);
    }, { kind: SpanKind.CLIENT });
  }

  async getActiveSigningKey(): Promise<{ kid: string; kty: string; alg: string; use: string; public_key_pem: string; private_key_pem: string; status: 'ACTIVE' | 'RETIRED'; created_at_ms: number } | null> {
    return withSpan('RealPostgresAuthAdapter.getActiveSigningKey', async () => {
      const sql = `SELECT kid, kty, alg, use, public_key_pem, private_key_pem, status, created_at_ms FROM auth_signing_keys WHERE status = 'ACTIVE' ORDER BY created_at_ms DESC LIMIT 1`;
      const res = await this.pool.query(sql);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        kid: row.kid,
        kty: row.kty,
        alg: row.alg,
        use: row.use,
        public_key_pem: row.public_key_pem,
        private_key_pem: row.private_key_pem,
        status: row.status,
        created_at_ms: Number(row.created_at_ms),
      };
    }, { kind: SpanKind.CLIENT });
  }

  async saveSamlProvider(provider: any): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.saveSamlProvider', async () => {
      await this.pool.query(this.queries.SAML.UPSERT_PROVIDER, [
        provider.id,
        provider.org_id,
        provider.idp_entity_id,
        provider.idp_sso_url,
        provider.idp_certificate_pem,
        provider.sp_entity_id,
        JSON.stringify(provider.attribute_mapping || {}),
        provider.status,
        provider.created_at_ms,
      ]);
    }, { kind: SpanKind.CLIENT });
  }

  async findSamlProviderByOrgId(orgId: string): Promise<any | null> {
    return withSpan('RealPostgresAuthAdapter.findSamlProviderByOrgId', async () => {
      const res = await this.pool.query(this.queries.SAML.FIND_PROVIDER_BY_ORG_ID, [orgId]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        id: row.id,
        org_id: row.org_id,
        idp_entity_id: row.idp_entity_id,
        idp_sso_url: row.idp_sso_url,
        idp_certificate_pem: row.idp_certificate_pem,
        sp_entity_id: row.sp_entity_id,
        attribute_mapping: typeof row.attribute_mapping === 'string' ? JSON.parse(row.attribute_mapping) : row.attribute_mapping,
        status: row.status,
        created_at_ms: Number(row.created_at_ms),
        deleted_at: row.deleted_at,
      };
    }, { kind: SpanKind.CLIENT });
  }

  async findSamlProviderById(id: string): Promise<any | null> {
    return withSpan('RealPostgresAuthAdapter.findSamlProviderById', async () => {
      const res = await this.pool.query(this.queries.SAML.FIND_PROVIDER_BY_ID, [id]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        id: row.id,
        org_id: row.org_id,
        idp_entity_id: row.idp_entity_id,
        idp_sso_url: row.idp_sso_url,
        idp_certificate_pem: row.idp_certificate_pem,
        sp_entity_id: row.sp_entity_id,
        attribute_mapping: typeof row.attribute_mapping === 'string' ? JSON.parse(row.attribute_mapping) : row.attribute_mapping,
        status: row.status,
        created_at_ms: Number(row.created_at_ms),
        deleted_at: row.deleted_at,
      };
    }, { kind: SpanKind.CLIENT });
  }

  async listSamlProviders(orgId: string): Promise<ReadonlyArray<any>> {
    return withSpan('RealPostgresAuthAdapter.listSamlProviders', async () => {
      const res = await this.pool.query(this.queries.SAML.LIST_PROVIDERS_BY_ORG_ID, [orgId]);
      return res.rows.map((row) => ({
        id: row.id,
        org_id: row.org_id,
        idp_entity_id: row.idp_entity_id,
        idp_sso_url: row.idp_sso_url,
        idp_certificate_pem: row.idp_certificate_pem,
        sp_entity_id: row.sp_entity_id,
        attribute_mapping: typeof row.attribute_mapping === 'string' ? JSON.parse(row.attribute_mapping) : row.attribute_mapping,
        status: row.status,
        created_at_ms: Number(row.created_at_ms),
        deleted_at: row.deleted_at,
      }));
    }, { kind: SpanKind.CLIENT });
  }

  async saveSamlRequest(request: any): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.saveSamlRequest', async () => {
      await this.pool.query(this.queries.SAML.INSERT_REQUEST, [
        request.relay_state,
        request.org_id,
        request.provider_id,
        request.request_id,
        request.return_url ?? null,
        request.expires_at_ms,
        request.created_at_ms,
      ]);
    }, { kind: SpanKind.CLIENT });
  }

  async consumeSamlRequest(relayState: string): Promise<any | null> {
    return withSpan('RealPostgresAuthAdapter.consumeSamlRequest', async () => {
      const res = await this.pool.query(this.queries.SAML.CONSUME_REQUEST, [relayState]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        relay_state: row.relay_state,
        org_id: row.org_id,
        provider_id: row.provider_id,
        request_id: row.request_id,
        return_url: row.return_url,
        expires_at_ms: Number(row.expires_at_ms),
        created_at_ms: Number(row.created_at_ms),
      };
    }, { kind: SpanKind.CLIENT });
  }

  async recordAssertionId(assertionId: string, expiresAtMs: number): Promise<boolean> {
    return withSpan('RealPostgresAuthAdapter.recordAssertionId', async () => {
      try {
        await this.pool.query(this.queries.SAML.RECORD_ASSERTION_ID, [assertionId, expiresAtMs, Date.now()]);
        return true;
      } catch (err: any) {
        if (err?.code === '23505') {
          return false;
        }
        throw err;
      }
    }, { kind: SpanKind.CLIENT });
  }
}






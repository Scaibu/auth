import { Pool } from 'pg';
import { SpanKind } from '@chief-strategist-j/shared-infra';
import { AUTH_CONFIG } from '../../../config/env.config';
import type { AuthRepositoryPort, OrganizationRecord } from '../../../features/auth/repository';

import type { AuthUserRecord, AuditLogRecord } from '../../../features/auth/types';
import type { ApiKeyRecord, ClaimedDomainRecord, BlockedDomainRecord, RelationTuple, WebhookSubscriptionRecord, WebhookDeliveryRecord, BreakGlassSessionRecord } from '../../../shared/types/auth.types';
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

  public getPool(): Pool {
    return this.pool;
  }

  public async close(): Promise<void> {
    await this.pool.end();
  }

  private async setTenantRlsContext(client: any, orgId: string): Promise<void> {
    await client.query(AUTH_QUERIES.TENANT_RLS.SET_LOCAL_TENANT_CONTEXT, [orgId]);
    await client.query(AUTH_QUERIES.TENANT_RLS.SET_LOCAL_CURRENT_TENANT_ID, [orgId]);
  }

  async createOrganization(org: OrganizationRecord, creatorUserId?: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_CONSTANTS.TRANSACTION.BEGIN);
      const check = await client.query(AUTH_QUERIES.FLOW_CREATE_ORGANIZATION.CHECK_ORG_NAME, [org.name]);
      if (check.rows.length > 0) {
        throw new Error(`Organization name already exists: ${org.name}`);
      }
      await client.query(AUTH_QUERIES.FLOW_CREATE_ORGANIZATION.INSERT_ORG, [org.id, org.name, org.slug]);
      if (creatorUserId) {
        await client.query(AUTH_QUERIES.FLOW_CREATE_ORGANIZATION.INSERT_USER_ORG, [creatorUserId, org.id, AUTH_CONSTANTS.ROLE_ADMIN]);
      }
      await client.query(AUTH_CONSTANTS.TRANSACTION.COMMIT);
    } catch (err) {
      await client.query(AUTH_CONSTANTS.TRANSACTION.ROLLBACK);
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
      await client.query(AUTH_CONSTANTS.TRANSACTION.BEGIN);
      await client.query(AUTH_QUERIES.FLOW_DELETE_ORGANIZATION.SOFT_DELETE_ORG, [orgId]);
      await client.query(AUTH_QUERIES.FLOW_DELETE_ORGANIZATION.CASCADE_SOFT_DELETE_USERS, [orgId]);
      await client.query(AUTH_QUERIES.FLOW_DELETE_ORGANIZATION.CASCADE_SOFT_DELETE_KEYS, [orgId]);
      await client.query(AUTH_QUERIES.FLOW_DELETE_ORGANIZATION.CASCADE_SOFT_DELETE_LOGS, [orgId]);
      await client.query(AUTH_CONSTANTS.TRANSACTION.COMMIT);
    } catch (err) {
      await client.query(AUTH_CONSTANTS.TRANSACTION.ROLLBACK);
      throw err;
    } finally {
      client.release();
    }
  }

  async createUser(userRecord: AuthUserRecord): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_CONSTANTS.TRANSACTION.BEGIN);
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
        userRecord.name_encrypted ?? null,
        userRecord.email_encrypted ?? null,
        userRecord.email_blind_index ?? null,
        userRecord.mfa_secret_encrypted ?? null,
      ]);
      await client.query(AUTH_QUERIES.FLOW_CREATE_USER.INSERT_USER_ORG, [userRecord.id, userRecord.org_id, userRecord.role ?? AUTH_CONSTANTS.ROLE_MEMBER]);
      await client.query(AUTH_CONSTANTS.TRANSACTION.COMMIT);
    } catch (err) {
      await client.query(AUTH_CONSTANTS.TRANSACTION.ROLLBACK);
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
        name_encrypted: row.name_encrypted ?? undefined,
        email_encrypted: row.email_encrypted ?? undefined,
        email_blind_index: row.email_blind_index ?? undefined,
        mfa_secret_encrypted: row.mfa_secret_encrypted ?? undefined,
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
      await client.query(AUTH_CONSTANTS.TRANSACTION.BEGIN);
      const r1 = await client.query(AUTH_QUERIES.FLOW_RETENTION_PURGE.PURGE_ORGS);
      const r2 = await client.query(AUTH_QUERIES.FLOW_RETENTION_PURGE.PURGE_USERS);
      const r3 = await client.query(AUTH_QUERIES.FLOW_RETENTION_PURGE.PURGE_KEYS);
      const r4 = await client.query(AUTH_QUERIES.FLOW_RETENTION_PURGE.PURGE_LOGS);
      const r5 = await client.query(AUTH_QUERIES.FLOW_RETENTION_PURGE.PURGE_RESETS);
      const r6 = await client.query(AUTH_QUERIES.FLOW_RETENTION_PURGE.PURGE_DENYLIST, [Date.now()]);
      const r7 = await client.query(AUTH_QUERIES.FLOW_RETENTION_PURGE.PURGE_REFRESH_TOKENS);
      await client.query(AUTH_CONSTANTS.TRANSACTION.COMMIT);
      return (r1.rowCount ?? 0) + (r2.rowCount ?? 0) + (r3.rowCount ?? 0) + (r4.rowCount ?? 0) + (r5.rowCount ?? 0) + (r6.rowCount ?? 0) + (r7.rowCount ?? 0);
    } catch (err) {
      await client.query(AUTH_CONSTANTS.TRANSACTION.ROLLBACK);
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
        const res = await client.query(AUTH_QUERIES.FLOW_SIGN_IN.FIND_USER_BY_EMAIL, [email, email]);
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
          name_encrypted: row.name_encrypted ?? undefined,
          email_encrypted: row.email_encrypted ?? undefined,
          email_blind_index: row.email_blind_index ?? undefined,
          mfa_secret_encrypted: row.mfa_secret_encrypted ?? undefined,
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
        name_encrypted: row.name_encrypted ?? undefined,
        email_encrypted: row.email_encrypted ?? undefined,
        email_blind_index: row.email_blind_index ?? undefined,
        mfa_secret_encrypted: row.mfa_secret_encrypted ?? undefined,
      };
    } finally {
      client.release();
    }
  }

  async createOrganizationAndUser(userRecord: AuthUserRecord): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_CONSTANTS.TRANSACTION.BEGIN);
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
        userRecord.name_encrypted ?? null,
        userRecord.email_encrypted ?? null,
        userRecord.email_blind_index ?? null,
        userRecord.mfa_secret_encrypted ?? null,
      ]);
      await client.query(AUTH_QUERIES.FLOW_SIGN_UP.INSERT_USER_ORG, [userRecord.id, userRecord.org_id, userRecord.role ?? AUTH_CONSTANTS.ROLE_ADMIN]);
      await client.query(AUTH_CONSTANTS.TRANSACTION.COMMIT);
    } catch (err) {
      await client.query(AUTH_CONSTANTS.TRANSACTION.ROLLBACK);
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
        keyRecord.ip_allowlist ?? [],
        keyRecord.rate_quota_rpm ?? null,
        keyRecord.total_requests_count ?? 0,
        keyRecord.anomaly_flag ?? false,
        keyRecord.anomaly_flagged_at_ms ?? null,
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
        ip_allowlist: row.ip_allowlist ?? [],
        rate_quota_rpm: row.rate_quota_rpm ?? null,
        total_requests_count: parseInt(row.total_requests_count ?? '0', 10),
        anomaly_flag: row.anomaly_flag ?? false,
        anomaly_flagged_at_ms: row.anomaly_flagged_at_ms ? parseInt(row.anomaly_flagged_at_ms, 10) : null,
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
        ip_allowlist: row.ip_allowlist ?? [],
        rate_quota_rpm: row.rate_quota_rpm ?? null,
        total_requests_count: parseInt(row.total_requests_count ?? '0', 10),
        anomaly_flag: row.anomaly_flag ?? false,
        anomaly_flagged_at_ms: row.anomaly_flagged_at_ms ? parseInt(row.anomaly_flagged_at_ms, 10) : null,
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

  async updateApiKeyAllowlist(keyId: string, ipAllowlist: readonly string[]): Promise<{ key_id: string; org_id: string; ip_allowlist: string[]; rate_quota_rpm: number | null } | null> {
    const client = await this.pool.connect();
    try {
      const res = await client.query(AUTH_QUERIES.FLOW_API_KEY_ALLOWLIST.UPDATE_ALLOWLIST, [[...ipAllowlist], keyId]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return { key_id: row.key_id, org_id: row.org_id, ip_allowlist: row.ip_allowlist ?? [], rate_quota_rpm: row.rate_quota_rpm ?? null };
    } finally {
      client.release();
    }
  }

  async findApiKeyMeta(keyId: string): Promise<{ key_id: string; org_id: string; ip_allowlist: string[]; rate_quota_rpm: number | null; anomaly_flag: boolean } | null> {
    const client = await this.pool.connect();
    try {
      const res = await client.query(AUTH_QUERIES.FLOW_API_KEY_ALLOWLIST.GET_KEY_META, [keyId]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return { key_id: row.key_id, org_id: row.org_id, ip_allowlist: row.ip_allowlist ?? [], rate_quota_rpm: row.rate_quota_rpm ?? null, anomaly_flag: row.anomaly_flag ?? false };
    } finally {
      client.release();
    }
  }

  async flagApiKeyAnomaly(keyId: string, flaggedAtMs: number): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(AUTH_QUERIES.FLOW_API_KEY_ANOMALY.FLAG_KEY, [flaggedAtMs, keyId]);
    } finally {
      client.release();
    }
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


  async saveCustomRole(role: any): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.saveCustomRole', async () => {
      await this.pool.query(this.queries.FLOW_CUSTOM_ROLES.INSERT_ROLE, [
        role.id,
        role.public_id || `pub_${role.id}`,
        role.org_id,
        role.name,
        role.description || '',
        role.permission_mask,
        Boolean(role.is_system_role),
        role.version || 1,
        role.created_at_ms,
        role.updated_at_ms,
      ]);
    }, { kind: SpanKind.CLIENT });
  }

  async findCustomRoleById(id: string, orgId: string): Promise<any | null> {
    return withSpan('RealPostgresAuthAdapter.findCustomRoleById', async () => {
      const res = await this.pool.query(this.queries.FLOW_CUSTOM_ROLES.FIND_ROLE_BY_ID, [id, orgId]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        id: row.id,
        public_id: row.public_id,
        org_id: row.org_id,
        name: row.name,
        description: row.description,
        permission_mask: row.permission_mask,
        is_system_role: Boolean(row.is_system_role),
        version: Number(row.version),
        created_at_ms: Number(row.created_at_ms),
        updated_at_ms: Number(row.updated_at_ms),
      };
    }, { kind: SpanKind.CLIENT });
  }

  async findCustomRoleByName(name: string, orgId: string): Promise<any | null> {
    return withSpan('RealPostgresAuthAdapter.findCustomRoleByName', async () => {
      const res = await this.pool.query(this.queries.FLOW_CUSTOM_ROLES.FIND_ROLE_BY_NAME, [orgId, name]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        id: row.id,
        public_id: row.public_id,
        org_id: row.org_id,
        name: row.name,
        description: row.description,
        permission_mask: row.permission_mask,
        is_system_role: Boolean(row.is_system_role),
        version: Number(row.version),
        created_at_ms: Number(row.created_at_ms),
        updated_at_ms: Number(row.updated_at_ms),
      };
    }, { kind: SpanKind.CLIENT });
  }

  async listCustomRolesByOrgId(orgId: string): Promise<any[]> {
    return withSpan('RealPostgresAuthAdapter.listCustomRolesByOrgId', async () => {
      const res = await this.pool.query(this.queries.FLOW_CUSTOM_ROLES.LIST_ROLES_BY_ORG, [orgId]);
      return res.rows.map((row: any) => ({
        id: row.id,
        public_id: row.public_id,
        org_id: row.org_id,
        name: row.name,
        description: row.description,
        permission_mask: row.permission_mask,
        is_system_role: Boolean(row.is_system_role),
        version: Number(row.version),
        created_at_ms: Number(row.created_at_ms),
        updated_at_ms: Number(row.updated_at_ms),
      }));
    }, { kind: SpanKind.CLIENT });
  }

  async updateCustomRole(id: string, orgId: string, patch: { name?: string; description?: string; permission_mask?: string }): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.updateCustomRole', async () => {
      await this.pool.query(this.queries.FLOW_CUSTOM_ROLES.UPDATE_ROLE, [
        id,
        orgId,
        patch.name ?? null,
        patch.description ?? null,
        patch.permission_mask ?? null,
        Date.now(),
      ]);
    }, { kind: SpanKind.CLIENT });
  }

  async deleteCustomRole(id: string, orgId: string): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.deleteCustomRole', async () => {
      await this.pool.query(this.queries.FLOW_CUSTOM_ROLES.DELETE_ROLE, [id, orgId]);
    }, { kind: SpanKind.CLIENT });
  }

  async assignUserCustomRoles(orgId: string, userId: string, roleIds: readonly string[], _assignedBy?: string): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.assignUserCustomRoles', async () => {
      const client = await this.pool.connect();
      try {
        await client.query(AUTH_CONSTANTS.TRANSACTION.BEGIN);
        await client.query(this.queries.FLOW_CUSTOM_ROLES.DELETE_USER_ROLES, [orgId, userId]);
        const now = Date.now();
        for (const roleId of roleIds) {
          const ucroleId = `ucrole_${crypto.randomUUID()}`;
          const pubId = `pub_${ucroleId}`;
          await client.query(this.queries.FLOW_CUSTOM_ROLES.INSERT_USER_ROLE, [
            ucroleId,
            pubId,
            orgId,
            userId,
            roleId,
            now,
          ]);
        }
        await client.query(AUTH_CONSTANTS.TRANSACTION.COMMIT);
      } catch (err) {
        await client.query(AUTH_CONSTANTS.TRANSACTION.ROLLBACK);
        throw err;
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async listUserCustomRoles(orgId: string, userId: string): Promise<any[]> {
    return withSpan('RealPostgresAuthAdapter.listUserCustomRoles', async () => {
      const res = await this.pool.query(this.queries.FLOW_CUSTOM_ROLES.LIST_USER_ROLES, [orgId, userId]);
      return res.rows.map((row: any) => ({
        id: row.id,
        public_id: row.public_id,
        org_id: row.org_id,
        name: row.name,
        description: row.description,
        permission_mask: row.permission_mask,
        is_system_role: Boolean(row.is_system_role),
        version: Number(row.version),
        created_at_ms: Number(row.created_at_ms),
        updated_at_ms: Number(row.updated_at_ms),
      }));
    }, { kind: SpanKind.CLIENT });
  }

  async recordRoleAuditLog(log: any): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.recordRoleAuditLog', async () => {
      await this.pool.query(
        this.queries.FLOW_CUSTOM_ROLES.INSERT_AUDIT_LOG,
        [
          log.id,
          log.org_id,
          log.actor_user_id,
          log.action,
          log.target_role_id,
          log.target_user_id ?? null,
          log.previous_mask ?? null,
          log.new_mask ?? null,
          log.reason ?? '',
          log.created_at_ms,
        ]
      );
    }, { kind: SpanKind.CLIENT });
  }

  async saveMagicLink(record: any): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.saveMagicLink', async () => {
      await this.pool.query(this.queries.FLOW_MAGIC_LINKS.INSERT_MAGIC_LINK, [
        record.id,
        record.public_id,
        record.org_id,
        record.user_id,
        record.email,
        record.token_hash,
        record.redirect_url ?? null,
        record.request_ip ?? null,
        record.user_agent_hash ?? null,
        record.version || 1,
        record.expires_at_ms,
        record.created_at_ms,
        record.updated_at_ms,
      ]);
    }, { kind: SpanKind.CLIENT });
  }

  async findMagicLinkByHash(tokenHash: string): Promise<any | null> {
    return withSpan('RealPostgresAuthAdapter.findMagicLinkByHash', async () => {
      const res = await this.pool.query(this.queries.FLOW_MAGIC_LINKS.FIND_BY_HASH, [tokenHash]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        id: row.id,
        public_id: row.public_id,
        org_id: row.org_id,
        user_id: row.user_id,
        email: row.email,
        token_hash: row.token_hash,
        redirect_url: row.redirect_url,
        request_ip: row.request_ip,
        user_agent_hash: row.user_agent_hash,
        consumed_at_ms: row.consumed_at_ms ? Number(row.consumed_at_ms) : null,
        consumed_ip: row.consumed_ip,
        superseded_at_ms: row.superseded_at_ms ? Number(row.superseded_at_ms) : null,
        version: Number(row.version),
        expires_at_ms: Number(row.expires_at_ms),
        created_at_ms: Number(row.created_at_ms),
        updated_at_ms: Number(row.updated_at_ms),
      };
    }, { kind: SpanKind.CLIENT });
  }

  async supersedePendingMagicLinks(orgId: string, userId: string, supersededAtMs: number): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.supersedePendingMagicLinks', async () => {
      await this.pool.query(this.queries.FLOW_MAGIC_LINKS.SUPERSEDE_USER_PENDING, [orgId, userId, supersededAtMs]);
    }, { kind: SpanKind.CLIENT });
  }

  async consumeMagicLink(tokenHash: string, consumedAtMs: number, consumedIp?: string): Promise<boolean> {
    return withSpan('RealPostgresAuthAdapter.consumeMagicLink', async () => {
      const res = await this.pool.query(this.queries.FLOW_MAGIC_LINKS.CONSUME_LINK, [tokenHash, consumedAtMs, consumedIp ?? null]);
      return (res.rowCount ?? 0) > 0;
    }, { kind: SpanKind.CLIENT });
  }

  async countRecentMagicLinksByEmail(email: string, sinceEpochMs: number): Promise<number> {
    return withSpan('RealPostgresAuthAdapter.countRecentMagicLinksByEmail', async () => {
      const res = await this.pool.query(this.queries.FLOW_MAGIC_LINKS.COUNT_RECENT_BY_EMAIL, [email, sinceEpochMs]);
      return Number(res.rows[0]?.count ?? 0);
    }, { kind: SpanKind.CLIENT });
  }

  async countRecentMagicLinksByIp(ip: string, sinceEpochMs: number): Promise<number> {
    return withSpan('RealPostgresAuthAdapter.countRecentMagicLinksByIp', async () => {
      const res = await this.pool.query(this.queries.FLOW_MAGIC_LINKS.COUNT_RECENT_BY_IP, [ip, sinceEpochMs]);
      return Number(res.rows[0]?.count ?? 0);
    }, { kind: SpanKind.CLIENT });
  }

  async saveWebhookSubscription(subscription: WebhookSubscriptionRecord): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.saveWebhookSubscription', async () => {
      await this.pool.query(this.queries.FLOW_WEBHOOKS.INSERT_SUBSCRIPTION, [
        subscription.id,
        subscription.public_id,
        subscription.org_id,
        subscription.target_url,
        subscription.secret_hash,
        subscription.secret_prefix,
        JSON.stringify(subscription.subscribed_events),
        subscription.active,
        subscription.version,
        subscription.created_at_ms,
        subscription.updated_at_ms,
      ]);
    }, { kind: SpanKind.CLIENT });
  }

  async findWebhookSubscriptionById(id: string, orgId: string): Promise<WebhookSubscriptionRecord | null> {
    return withSpan('RealPostgresAuthAdapter.findWebhookSubscriptionById', async () => {
      const res = await this.pool.query(this.queries.FLOW_WEBHOOKS.FIND_SUBSCRIPTION_BY_ID, [id, orgId]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        id: row.id,
        public_id: row.public_id,
        org_id: row.org_id,
        target_url: row.target_url,
        secret_hash: row.secret_hash,
        secret_prefix: row.secret_prefix,
        subscribed_events: typeof row.subscribed_events === 'string' ? JSON.parse(row.subscribed_events) : row.subscribed_events,
        active: Boolean(row.active),
        version: Number(row.version),
        created_at_ms: Number(row.created_at_ms),
        updated_at_ms: Number(row.updated_at_ms),
      };
    }, { kind: SpanKind.CLIENT });
  }

  async listWebhookSubscriptionsByOrgId(orgId: string): Promise<WebhookSubscriptionRecord[]> {
    return withSpan('RealPostgresAuthAdapter.listWebhookSubscriptionsByOrgId', async () => {
      const res = await this.pool.query(this.queries.FLOW_WEBHOOKS.LIST_SUBSCRIPTIONS_BY_ORG, [orgId]);
      return res.rows.map((row: any) => ({
        id: row.id,
        public_id: row.public_id,
        org_id: row.org_id,
        target_url: row.target_url,
        secret_hash: row.secret_hash,
        secret_prefix: row.secret_prefix,
        subscribed_events: typeof row.subscribed_events === 'string' ? JSON.parse(row.subscribed_events) : row.subscribed_events,
        active: Boolean(row.active),
        version: Number(row.version),
        created_at_ms: Number(row.created_at_ms),
        updated_at_ms: Number(row.updated_at_ms),
      }));
    }, { kind: SpanKind.CLIENT });
  }

  async updateWebhookSubscription(
    id: string,
    orgId: string,
    patch: { target_url?: string; subscribed_events?: readonly string[]; active?: boolean }
  ): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.updateWebhookSubscription', async () => {
      await this.pool.query(this.queries.FLOW_WEBHOOKS.UPDATE_SUBSCRIPTION, [
        id,
        orgId,
        patch.target_url ?? null,
        patch.subscribed_events ? JSON.stringify(patch.subscribed_events) : null,
        patch.active ?? null,
        Date.now(),
      ]);
    }, { kind: SpanKind.CLIENT });
  }

  async deleteWebhookSubscription(id: string, orgId: string): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.deleteWebhookSubscription', async () => {
      await this.pool.query(this.queries.FLOW_WEBHOOKS.DELETE_SUBSCRIPTION, [id, orgId]);
    }, { kind: SpanKind.CLIENT });
  }

  async recordWebhookDelivery(delivery: WebhookDeliveryRecord): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.recordWebhookDelivery', async () => {
      await this.pool.query(this.queries.FLOW_WEBHOOKS.INSERT_DELIVERY, [
        delivery.id,
        delivery.public_id,
        delivery.subscription_id,
        delivery.org_id,
        delivery.event_type,
        delivery.nonce,
        delivery.response_status,
        delivery.execution_duration_ms,
        delivery.success,
        delivery.failure_reason ?? null,
        delivery.delivered_at_ms,
      ]);
    }, { kind: SpanKind.CLIENT });
  }

  async listWebhookDeliveriesBySubscriptionId(subscriptionId: string, orgId: string): Promise<WebhookDeliveryRecord[]> {
    return withSpan('RealPostgresAuthAdapter.listWebhookDeliveriesBySubscriptionId', async () => {
      const res = await this.pool.query(this.queries.FLOW_WEBHOOKS.LIST_DELIVERIES_BY_SUB, [subscriptionId, orgId]);
      return res.rows.map((row: any) => ({
        id: row.id,
        public_id: row.public_id,
        subscription_id: row.subscription_id,
        org_id: row.org_id,
        event_type: row.event_type,
        nonce: row.nonce,
        response_status: Number(row.response_status),
        execution_duration_ms: Number(row.execution_duration_ms),
        success: Boolean(row.success),
        failure_reason: row.failure_reason,
        delivered_at_ms: Number(row.delivered_at_ms),
      }));
    }, { kind: SpanKind.CLIENT });
  }

  async saveUserEncryptionKey(keyRecord: { id: string; user_id: string; org_id: string; kid: string; encrypted_dek: string }): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.saveUserEncryptionKey', async () => {
      const client = await this.pool.connect();
      try {
        await client.query(this.queries.FLOW_USER_KEYS.INSERT_KEY, [
          keyRecord.id,
          keyRecord.user_id,
          keyRecord.org_id,
          keyRecord.kid,
          keyRecord.encrypted_dek,
        ]);
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async findUserEncryptionKey(userId: string): Promise<{ id: string; user_id: string; org_id: string; kid: string; encrypted_dek: string; dek_status: 'ACTIVE' | 'SHREDDED'; shredded_at?: string } | null> {
    return withSpan('RealPostgresAuthAdapter.findUserEncryptionKey', async () => {
      const client = await this.pool.connect();
      try {
        const res = await client.query(this.queries.FLOW_USER_KEYS.FIND_KEY_BY_USER_ID, [userId]);
        if (res.rows.length === 0) return null;
        const row = res.rows[0];
        return {
          id: row.id,
          user_id: row.user_id,
          org_id: row.org_id,
          kid: row.kid,
          encrypted_dek: row.encrypted_dek,
          dek_status: row.dek_status,
          shredded_at: row.shredded_at ? new Date(row.shredded_at).toISOString() : undefined,
        };
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async shredUserEncryptionKey(userId: string): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.shredUserEncryptionKey', async () => {
      const client = await this.pool.connect();
      try {
        const randomNoise = `enc:v1:${Buffer.from(crypto.randomUUID()).toString('base64url')}`;
        await client.query(this.queries.FLOW_USER_KEYS.SHRED_KEY_BY_USER_ID, [userId, randomNoise]);
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async saveBreakGlassSession(session: BreakGlassSessionRecord): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.saveBreakGlassSession', async () => {
      const client = await this.pool.connect();
      try {
        await client.query(this.queries.FLOW_BREAK_GLASS.INSERT_SESSION, [
          session.id,
          session.org_id,
          session.user_id,
          session.incident_ticket_id,
          session.justification,
          session.token_hash,
          session.elevated_role,
          session.activated_at,
          session.expires_at,
        ]);
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async findBreakGlassSessionById(id: string): Promise<BreakGlassSessionRecord | null> {
    return withSpan('RealPostgresAuthAdapter.findBreakGlassSessionById', async () => {
      const client = await this.pool.connect();
      try {
        const res = await client.query(this.queries.FLOW_BREAK_GLASS.FIND_SESSION_BY_ID, [id]);
        if (res.rows.length === 0) return null;
        const row = res.rows[0];
        return {
          id: row.id,
          org_id: row.org_id,
          user_id: row.user_id,
          incident_ticket_id: row.incident_ticket_id,
          justification: row.justification,
          status: row.status,
          token_hash: row.token_hash,
          elevated_role: row.elevated_role,
          activated_at: typeof row.activated_at === 'string' ? row.activated_at : row.activated_at.toISOString(),
          expires_at: typeof row.expires_at === 'string' ? row.expires_at : row.expires_at.toISOString(),
          terminated_at: row.terminated_at ? (typeof row.terminated_at === 'string' ? row.terminated_at : row.terminated_at.toISOString()) : null,
          terminated_by: row.terminated_by,
          terminated_reason: row.terminated_reason,
          created_at: row.created_at ? (typeof row.created_at === 'string' ? row.created_at : row.created_at.toISOString()) : undefined,
          updated_at: row.updated_at ? (typeof row.updated_at === 'string' ? row.updated_at : row.updated_at.toISOString()) : undefined,
        };
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async findBreakGlassSessionByHash(tokenHash: string): Promise<BreakGlassSessionRecord | null> {
    return withSpan('RealPostgresAuthAdapter.findBreakGlassSessionByHash', async () => {
      const client = await this.pool.connect();
      try {
        const res = await client.query(this.queries.FLOW_BREAK_GLASS.FIND_SESSION_BY_HASH, [tokenHash]);
        if (res.rows.length === 0) return null;
        const row = res.rows[0];
        return {
          id: row.id,
          org_id: row.org_id,
          user_id: row.user_id,
          incident_ticket_id: row.incident_ticket_id,
          justification: row.justification,
          status: row.status,
          token_hash: row.token_hash,
          elevated_role: row.elevated_role,
          activated_at: typeof row.activated_at === 'string' ? row.activated_at : row.activated_at.toISOString(),
          expires_at: typeof row.expires_at === 'string' ? row.expires_at : row.expires_at.toISOString(),
          terminated_at: row.terminated_at ? (typeof row.terminated_at === 'string' ? row.terminated_at : row.terminated_at.toISOString()) : null,
          terminated_by: row.terminated_by,
          terminated_reason: row.terminated_reason,
          created_at: row.created_at ? (typeof row.created_at === 'string' ? row.created_at : row.created_at.toISOString()) : undefined,
          updated_at: row.updated_at ? (typeof row.updated_at === 'string' ? row.updated_at : row.updated_at.toISOString()) : undefined,
        };
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async listActiveBreakGlassSessions(orgId?: string): Promise<BreakGlassSessionRecord[]> {
    return withSpan('RealPostgresAuthAdapter.listActiveBreakGlassSessions', async () => {
      const client = await this.pool.connect();
      try {
        const res = await client.query(this.queries.FLOW_BREAK_GLASS.LIST_ACTIVE_SESSIONS, [orgId ?? null]);
        return res.rows.map((row) => ({
          id: row.id,
          org_id: row.org_id,
          user_id: row.user_id,
          incident_ticket_id: row.incident_ticket_id,
          justification: row.justification,
          status: row.status,
          token_hash: row.token_hash,
          elevated_role: row.elevated_role,
          activated_at: typeof row.activated_at === 'string' ? row.activated_at : row.activated_at.toISOString(),
          expires_at: typeof row.expires_at === 'string' ? row.expires_at : row.expires_at.toISOString(),
          terminated_at: row.terminated_at ? (typeof row.terminated_at === 'string' ? row.terminated_at : row.terminated_at.toISOString()) : null,
          terminated_by: row.terminated_by,
          terminated_reason: row.terminated_reason,
          created_at: row.created_at ? (typeof row.created_at === 'string' ? row.created_at : row.created_at.toISOString()) : undefined,
          updated_at: row.updated_at ? (typeof row.updated_at === 'string' ? row.updated_at : row.updated_at.toISOString()) : undefined,
        }));
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async terminateBreakGlassSession(id: string, terminatedBy: string, reason: string, terminatedAt: string): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.terminateBreakGlassSession', async () => {
      const client = await this.pool.connect();
      try {
        await client.query(this.queries.FLOW_BREAK_GLASS.TERMINATE_SESSION, [id, terminatedAt, terminatedBy, reason]);
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async saveHoneytoken(honeytoken: {
    id: string;
    token_hash: string;
    token_prefix: string;
    name: string;
    org_id: string;
    deployed_location?: string | null;
    tripwire_count: number;
    last_tripped_at_ms?: number | null;
    last_tripped_ip?: string | null;
    last_tripped_user_agent?: string | null;
    status: 'ACTIVE' | 'TRIPPED' | 'REVOKED';
    created_at_ms: number;
  }): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.saveHoneytoken', async () => {
      const client = await this.pool.connect();
      try {
        await client.query(this.queries.HONEYTOKEN.INSERT, [
          honeytoken.id,
          honeytoken.token_hash,
          honeytoken.token_prefix,
          honeytoken.name,
          honeytoken.org_id,
          honeytoken.deployed_location || null,
          honeytoken.tripwire_count,
          honeytoken.status,
          honeytoken.created_at_ms,
        ]);
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async findHoneytokenByHash(tokenHash: string): Promise<{
    id: string;
    token_hash: string;
    token_prefix: string;
    name: string;
    org_id: string;
    deployed_location?: string | null;
    tripwire_count: number;
    last_tripped_at_ms?: number | null;
    last_tripped_ip?: string | null;
    last_tripped_user_agent?: string | null;
    status: 'ACTIVE' | 'TRIPPED' | 'REVOKED';
    created_at_ms: number;
  } | null> {
    return await withSpan('RealPostgresAuthAdapter.findHoneytokenByHash', async () => {
      const client = await this.pool.connect();
      try {
        const res = await client.query(this.queries.HONEYTOKEN.FIND_BY_HASH, [tokenHash]);
        if (res.rows.length === 0) return null;
        const row = res.rows[0];
        return {
          id: row.id,
          token_hash: row.token_hash,
          token_prefix: row.token_prefix,
          name: row.name,
          org_id: row.org_id,
          deployed_location: row.deployed_location,
          tripwire_count: Number(row.tripwire_count),
          last_tripped_at_ms: row.last_tripped_at_ms ? Number(row.last_tripped_at_ms) : null,
          last_tripped_ip: row.last_tripped_ip,
          last_tripped_user_agent: row.last_tripped_user_agent,
          status: row.status,
          created_at_ms: Number(row.created_at_ms),
        };
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async recordHoneytokenTrip(id: string, metadata: { ip: string; userAgent: string; timestampMs: number }): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.recordHoneytokenTrip', async () => {
      const client = await this.pool.connect();
      try {
        await client.query(this.queries.HONEYTOKEN.RECORD_TRIP, [
          id,
          metadata.timestampMs,
          metadata.ip,
          metadata.userAgent,
        ]);
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async listHoneytokensByOrgId(orgId: string): Promise<Array<{
    id: string;
    token_hash: string;
    token_prefix: string;
    name: string;
    org_id: string;
    deployed_location?: string | null;
    tripwire_count: number;
    last_tripped_at_ms?: number | null;
    last_tripped_ip?: string | null;
    last_tripped_user_agent?: string | null;
    status: 'ACTIVE' | 'TRIPPED' | 'REVOKED';
    created_at_ms: number;
  }>> {
    return await withSpan('RealPostgresAuthAdapter.listHoneytokensByOrgId', async () => {
      const client = await this.pool.connect();
      try {
        const res = await client.query(this.queries.HONEYTOKEN.LIST_BY_ORG, [orgId]);
        return res.rows.map((row) => ({
          id: row.id,
          token_hash: row.token_hash,
          token_prefix: row.token_prefix,
          name: row.name,
          org_id: row.org_id,
          deployed_location: row.deployed_location,
          tripwire_count: Number(row.tripwire_count),
          last_tripped_at_ms: row.last_tripped_at_ms ? Number(row.last_tripped_at_ms) : null,
          last_tripped_ip: row.last_tripped_ip,
          last_tripped_user_agent: row.last_tripped_user_agent,
          status: row.status,
          created_at_ms: Number(row.created_at_ms),
        }));
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async revokeHoneytoken(id: string, orgId: string): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.revokeHoneytoken', async () => {
      const client = await this.pool.connect();
      try {
        await client.query(this.queries.HONEYTOKEN.REVOKE, [id, orgId]);
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async fetchAuditLogsForWormSealing(fromMs: number, toMs: number): Promise<AuditLogRecord[]> {
    return await withSpan('RealPostgresAuthAdapter.fetchAuditLogsForWormSealing', async () => {
      const client = await this.pool.connect();
      try {
        const res = await client.query(this.queries.WORM_AUDIT.FETCH_LOGS_FOR_SEALING, [fromMs, toMs]);
        return res.rows.map((row) => ({
          id: row.id,
          user_id: row.user_id,
          org_id: row.org_id,
          event_type: row.event_type,
          ip_address: row.ip_address,
          user_agent: row.user_agent,
          timestamp_ms: Number(row.timestamp_ms),
        }));
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async saveWormAuditArchive(archive: {
    id: string;
    segment_start_ms: number;
    segment_end_ms: number;
    record_count: number;
    merkle_root: string;
    storage_location: string;
    storage_version_id?: string | null;
    retention_until_ms: number;
    status: 'PENDING' | 'SEALED' | 'FAILED';
    sealed_by_user_id: string;
    created_at_ms: number;
  }): Promise<void> {
    await withSpan('RealPostgresAuthAdapter.saveWormAuditArchive', async () => {
      const client = await this.pool.connect();
      try {
        await client.query(this.queries.WORM_AUDIT.INSERT_ARCHIVE, [
          archive.id,
          archive.segment_start_ms,
          archive.segment_end_ms,
          archive.record_count,
          archive.merkle_root,
          archive.storage_location,
          archive.storage_version_id ?? null,
          archive.retention_until_ms,
          archive.status,
          archive.sealed_by_user_id,
          archive.created_at_ms,
        ]);
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async findWormAuditArchiveById(id: string): Promise<{
    id: string;
    segment_start_ms: number;
    segment_end_ms: number;
    record_count: number;
    merkle_root: string;
    storage_location: string;
    storage_version_id?: string | null;
    retention_until_ms: number;
    status: 'PENDING' | 'SEALED' | 'FAILED';
    sealed_by_user_id: string;
    created_at_ms: number;
  } | null> {
    return await withSpan('RealPostgresAuthAdapter.findWormAuditArchiveById', async () => {
      const client = await this.pool.connect();
      try {
        const res = await client.query(this.queries.WORM_AUDIT.FIND_ARCHIVE_BY_ID, [id]);
        if (res.rows.length === 0) return null;
        const row = res.rows[0];
        return {
          id: row.id,
          segment_start_ms: Number(row.segment_start_ms),
          segment_end_ms: Number(row.segment_end_ms),
          record_count: Number(row.record_count),
          merkle_root: row.merkle_root,
          storage_location: row.storage_location,
          storage_version_id: row.storage_version_id,
          retention_until_ms: Number(row.retention_until_ms),
          status: row.status,
          sealed_by_user_id: row.sealed_by_user_id,
          created_at_ms: Number(row.created_at_ms),
        };
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async listWormAuditArchives(): Promise<Array<{
    id: string;
    segment_start_ms: number;
    segment_end_ms: number;
    record_count: number;
    merkle_root: string;
    storage_location: string;
    storage_version_id?: string | null;
    retention_until_ms: number;
    status: 'PENDING' | 'SEALED' | 'FAILED';
    sealed_by_user_id: string;
    created_at_ms: number;
  }>> {
    return await withSpan('RealPostgresAuthAdapter.listWormAuditArchives', async () => {
      const client = await this.pool.connect();
      try {
        const res = await client.query(this.queries.WORM_AUDIT.LIST_ARCHIVES);
        return res.rows.map((row) => ({
          id: row.id,
          segment_start_ms: Number(row.segment_start_ms),
          segment_end_ms: Number(row.segment_end_ms),
          record_count: Number(row.record_count),
          merkle_root: row.merkle_root,
          storage_location: row.storage_location,
          storage_version_id: row.storage_version_id,
          retention_until_ms: Number(row.retention_until_ms),
          status: row.status,
          sealed_by_user_id: row.sealed_by_user_id,
          created_at_ms: Number(row.created_at_ms),
        }));
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async fetchUserAuditLogs(userId: string, filters?: { event_type?: string; from_ms?: number; to_ms?: number }): Promise<AuditLogRecord[]> {
    return await withSpan('RealPostgresAuthAdapter.fetchUserAuditLogs', async () => {
      const client = await this.pool.connect();
      try {
        const query = filters?.event_type || filters?.from_ms !== undefined || filters?.to_ms !== undefined
          ? AUTH_QUERIES.FLOW_AUDIT_LOGS.FETCH_LOGS_BY_USER_FILTERED
          : AUTH_QUERIES.FLOW_AUDIT_LOGS.FETCH_LOGS_BY_USER;
        const params = filters?.event_type || filters?.from_ms !== undefined || filters?.to_ms !== undefined
          ? [userId, filters?.event_type ?? null, filters?.from_ms ?? null, filters?.to_ms ?? null]
          : [userId];
        const res = await client.query(query, params);
        return res.rows.map((row) => ({
          id: row.id,
          user_id: row.user_id,
          org_id: row.org_id,
          event_type: row.event_type,
          ip_address: row.ip_address,
          user_agent: row.user_agent,
          timestamp_ms: Number(row.timestamp_ms),
        }));
      } finally {
        client.release();
      }
    }, { kind: SpanKind.CLIENT });
  }

  async exportUserData(userId: string): Promise<{
    user: AuthUserRecord;
    organizations: OrganizationRecord[];
    apiKeys: ApiKeyRecord[];
    auditLogs: AuditLogRecord[];
  } | null> {
    return await withSpan('RealPostgresAuthAdapter.exportUserData', async () => {
      const user = await this.findUserById(userId);
      if (!user) return null;
      const organizations = await this.listOrganizationsByUserId(userId);
      const apiKeys = await this.listApiKeysByOrgId(user.org_id);
      const auditLogs = await this.fetchUserAuditLogs(userId);
      return {
        user,
        organizations,
        apiKeys,
        auditLogs,
      };
    }, { kind: SpanKind.CLIENT });
  }

  async insertOutboxEvent(event: {
    id: string;
    topic: string;
    eventName: string;
    partitionKey: string;
    payload: Record<string, unknown>;
    headers?: Record<string, string>;
  }): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(
        `INSERT INTO auth_outbox (id, topic, event_name, partition_key, headers, payload, status, retry_count, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'PENDING', 0, NOW())`,
        [
          event.id,
          event.topic,
          event.eventName,
          event.partitionKey,
          JSON.stringify(event.headers ?? {}),
          JSON.stringify(event.payload),
        ]
      );
    } finally {
      client.release();
    }
  }
}







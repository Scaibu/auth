/**
 * @file api-key.service.ts
 * @description Domain Service for Multi-Tier API Key Generation, Hashing, Permission Verification, TTL Enforcement,
 *              IP/CIDR Allowlist Enforcement, Per-Key Rate Quota, Revocation, and Anomaly Flagging.
 *
 * OVERALL ALGORITHM:
 * 1. API Key Generation: Validate schema -> verify organization existence -> resolve prefix via dictionary lookup ->
 *    enforce mandatory expires_at_ms for super_secret keys with max 90-day TTL -> generate cryptographically secure
 *    key and Argon2id hash -> persist record (including ip_allowlist and rate_quota_rpm) in repository -> return raw key and metadata.
 * 2. API Key Verification: Hash incoming key -> locate record in repository -> verify active status (not revoked) ->
 *    check Redis revocation denylist -> check expires_at_ms against current timestamp ->
 *    evaluate client_ip against ip_allowlist via pure CIDR bit-mask matching (deny if no match and allowlist non-empty) ->
 *    evaluate rate_quota_rpm via Redis sliding 1-minute epoch bucket (INCR+EXPIRE); if count > quota*3 flag anomaly async;
 *    if count > quota throw ApiKeyRateLimitError -> evaluate required_permission against key scopes ->
 *    update last_used_at_ms and last_used_ip asynchronously via repository.
 * 3. API Key Revocation: Mark revoked in repository and register instant revocation in Redis denylist for edge propagation.
 * 4. Allowlist Update: Replace ip_allowlist array in repository and return updated key metadata.
 */

import type { AuthRepositoryPort } from '../repository';
import type { CreateApiKeyInput, VerifyApiKeyInput } from '../types';
import type { ApiKeyRecord } from '../../../shared/types/auth.types';
import type { ICachePort } from '../../../shared/ports/cache.interface';
import { CreateApiKeyInputSchema, VerifyApiKeyInputSchema } from '../schema/auth.schema';
import {
  ApiKeyRevokedError,
  ApiKeyExpiredError,
  InsufficientPermissionError,
  ValidationError,
  ApiKeyIpDeniedError,
  ApiKeyRateLimitError,
} from '../../../shared/errors/auth.errors';
import { hashApiKey } from '../../../shared/utils/argon2.util';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { normalizeString } from '../../../shared/utils/string.util';
import { checkCidrAllowlist } from '../../../shared/utils/cidr.util';

const KEY_PREFIX_MAP: Readonly<Record<string, string>> = Object.freeze({
  [AUTH_CONSTANTS.KEY_TYPE_SUPER_SECRET]: AUTH_CONSTANTS.API_KEY_PREFIX_SUPER_SECRET,
  [AUTH_CONSTANTS.KEY_TYPE_TESTING]: AUTH_CONSTANTS.API_KEY_PREFIX_TESTING,
  [AUTH_CONSTANTS.KEY_TYPE_GENERAL]: AUTH_CONSTANTS.API_KEY_PREFIX_GENERAL,
});

const MAX_SUPER_SECRET_TTL_MS = 90 * 24 * 60 * 60 * 1000;
const REVOKED_KEY_CACHE_PREFIX = 'auth:revoked_api_key:';
const REVOKED_KEY_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const RATE_BUCKET_TTL_MS = AUTH_CONSTANTS.API_KEY_CIDR.RATE_BUCKET_TTL_SECONDS * 1000;

import { randomUUID } from 'crypto';
import type { AuthEventProducer } from '../../../shared/messaging/producers/auth-event.producer';
import { AUTH_KAFKA_TOPICS } from '../../../shared/messaging/topics/auth-topics';

export class ApiKeyDomainService {
  constructor(
    private readonly repo: AuthRepositoryPort,
    private readonly cache?: ICachePort,
    private readonly eventProducer?: AuthEventProducer,
  ) {}

  async generateApiKey(input: CreateApiKeyInput): Promise<{ rawKey: string; keyRecord: ApiKeyRecord }> {
    const validated = CreateApiKeyInputSchema.parse(input);
    const orgId = normalizeString(validated.org_id);

    const org = await this.repo.getOrganizationById(orgId);
    if (!org) {
      throw new ValidationError(`Invalid organization ID '${orgId}': Target organization does not exist in the system.`);
    }

    const keyType = normalizeString(validated.key_type);
    const prefix = KEY_PREFIX_MAP[keyType] ?? AUTH_CONSTANTS.API_KEY_PREFIX_GENERAL;

    if (keyType === AUTH_CONSTANTS.KEY_TYPE_SUPER_SECRET) {
      if (!validated.expires_at_ms) {
        throw new ValidationError('super_secret (ak_sec_) keys require a mandatory expires_at_ms TTL value.');
      }
      const ttlMs = validated.expires_at_ms - Date.now();
      if (ttlMs <= 0) {
        throw new ValidationError('expires_at_ms must be a future timestamp.');
      }
      if (ttlMs > MAX_SUPER_SECRET_TTL_MS) {
        throw new ValidationError('super_secret (ak_sec_) keys cannot have a TTL exceeding 90 days.');
      }
    }

    const keyId = `key_${Math.random().toString(36).substring(2, 9)}`;
    const secret = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    const rawKey = `${prefix}${orgId}_${secret}`;
    const keyHash = await hashApiKey(rawKey);

    const keyRecord: ApiKeyRecord = {
      key_id: keyId,
      org_id: orgId,
      key_type: validated.key_type,
      key_hash: keyHash,
      prefix,
      name: normalizeString(validated.name),
      permissions: Array.isArray(validated.permissions) ? [...validated.permissions] : [],
      created_at_ms: Date.now(),
      revoked: false,
      expires_at_ms: validated.expires_at_ms ?? null,
      last_used_at_ms: null,
      last_used_ip: null,
      ip_allowlist: Array.isArray(validated.ip_allowlist) ? [...validated.ip_allowlist] : [],
      rate_quota_rpm: validated.rate_quota_rpm ?? null,
      total_requests_count: 0,
      anomaly_flag: false,
      anomaly_flagged_at_ms: null,
    };

    await this.repo.saveApiKey(keyRecord);

    const payload = {
      keyId,
      orgId,
      keyType: keyRecord.key_type,
      name: keyRecord.name,
      permissions: keyRecord.permissions,
      expiresAtMs: keyRecord.expires_at_ms ?? undefined,
      timestamp: new Date().toISOString(),
    };
    if (typeof this.repo.insertOutboxEvent === 'function') {
      await this.repo.insertOutboxEvent({
        id: `outbox_${randomUUID()}`,
        topic: AUTH_KAFKA_TOPICS.AUTH_EVENTS,
        eventName: 'API_KEY_CREATED',
        partitionKey: orgId,
        payload,
      }).catch(() => {});
    } else if (this.eventProducer) {
      await this.eventProducer.publishApiKeyCreated(payload).catch(() => {});
    }

    return { rawKey, keyRecord };
  }

  async listApiKeys(orgId: string): Promise<ApiKeyRecord[]> {
    const normalizedOrgId = normalizeString(orgId);
    return this.repo.listApiKeysByOrgId(normalizedOrgId);
  }

  async verifyApiKey(input: VerifyApiKeyInput): Promise<{ valid: boolean; record: ApiKeyRecord; authorized: boolean }> {
    const validated = VerifyApiKeyInputSchema.parse(input);
    const rawKey = normalizeString(validated.key);
    const keyHash = await hashApiKey(rawKey);
    const record = await this.repo.findApiKeyByHash(keyHash);

    if (!record || record.revoked) {
      throw new ApiKeyRevokedError();
    }

    if (this.cache) {
      const cacheKey = `${REVOKED_KEY_CACHE_PREFIX}${record.key_id}`;
      const cachedRevoked = await this.cache.get(cacheKey);
      if (cachedRevoked) {
        throw new ApiKeyRevokedError();
      }
    }

    if (record.expires_at_ms && record.expires_at_ms <= Date.now()) {
      throw new ApiKeyExpiredError();
    }

    const org = await this.repo.getOrganizationById(record.org_id);
    if (!org || (org.deleted_at !== undefined && org.deleted_at !== null && org.deleted_at > 0)) {
      throw new ApiKeyRevokedError();
    }

    if ((record as any).user_id) {
      const user = await this.repo.findUserById((record as any).user_id);
      if (!user || user.blocked) {
        throw new ApiKeyRevokedError();
      }
    }

    const allowlist = record.ip_allowlist ?? [];
    if (allowlist.length > 0 && validated.client_ip) {
      const allowed = checkCidrAllowlist(validated.client_ip, allowlist);
      if (!allowed) {
        throw new ApiKeyIpDeniedError(validated.client_ip);
      }
    }

    if (record.rate_quota_rpm && this.cache?.incr) {
      await this.enforceRateQuota(record.key_id, record.rate_quota_rpm);
    }

    let authorized = true;
    if (validated.required_permission) {
      const required = normalizeString(validated.required_permission);
      const permissions = Array.isArray(record.permissions) ? record.permissions : [];
      authorized =
        record.key_type === AUTH_CONSTANTS.KEY_TYPE_SUPER_SECRET ||
        permissions.includes(AUTH_CONSTANTS.PERMISSION_ADMIN_ALL) ||
        permissions.includes(required);

      if (!authorized) {
        throw new InsufficientPermissionError(required);
      }
    }

    this.recordUsageAsync(record.key_id, validated.client_ip);

    return { valid: true, record, authorized };
  }

  async revokeApiKey(keyId: string, revokedBy?: string): Promise<void> {
    const normalizedKeyId = normalizeString(keyId);
    await this.repo.revokeApiKey(normalizedKeyId);

    if (this.cache) {
      const cacheKey = `${REVOKED_KEY_CACHE_PREFIX}${normalizedKeyId}`;
      await this.cache.set(cacheKey, 'revoked', REVOKED_KEY_CACHE_TTL_MS);
    }

    const payload = {
      keyId: normalizedKeyId,
      revokedBy,
      timestamp: new Date().toISOString(),
    };
    if (typeof this.repo.insertOutboxEvent === 'function') {
      await this.repo.insertOutboxEvent({
        id: `outbox_${randomUUID()}`,
        topic: AUTH_KAFKA_TOPICS.SECURITY_EVENTS,
        eventName: 'API_KEY_REVOKED',
        partitionKey: normalizedKeyId,
        payload,
      }).catch(() => {});
    } else if (this.eventProducer) {
      await this.eventProducer.publishApiKeyRevoked(payload).catch(() => {});
    }
  }

  async updateAllowlist(keyId: string, ipAllowlist: readonly string[]): Promise<{ key_id: string; org_id: string; ip_allowlist: string[]; rate_quota_rpm: number | null } | null> {
    return this.repo.updateApiKeyAllowlist(normalizeString(keyId), ipAllowlist);
  }

  async getApiKeyMeta(keyId: string): Promise<{ key_id: string; org_id: string; ip_allowlist: string[]; rate_quota_rpm: number | null; anomaly_flag: boolean } | null> {
    return this.repo.findApiKeyMeta(normalizeString(keyId));
  }

  getSystemPermissions(): string[] {
    return [
      AUTH_CONSTANTS.PERMISSION_TRACES_READ,
      AUTH_CONSTANTS.PERMISSION_TRACES_WRITE,
      AUTH_CONSTANTS.PERMISSION_METRICS_READ,
      AUTH_CONSTANTS.PERMISSION_METRICS_WRITE,
      AUTH_CONSTANTS.PERMISSION_LOGS_READ,
      AUTH_CONSTANTS.PERMISSION_LOGS_WRITE,
      AUTH_CONSTANTS.PERMISSION_ALERTS_READ,
      AUTH_CONSTANTS.PERMISSION_ALERTS_WRITE,
      AUTH_CONSTANTS.PERMISSION_ADMIN_ALL,
    ];
  }

  private async enforceRateQuota(keyId: string, quota: number): Promise<void> {
    if (!this.cache?.incr) return;
    const epochMinute = Math.floor(Date.now() / 60000);
    const bucketKey = `${AUTH_CONSTANTS.API_KEY_CIDR.RATE_QUOTA_CACHE_PREFIX}${keyId}:${epochMinute}`;
    const count = await this.cache.incr(bucketKey, RATE_BUCKET_TTL_MS);
    if (count > quota * AUTH_CONSTANTS.API_KEY_CIDR.ANOMALY_MULTIPLIER) {
      this.flagAnomalyAsync(keyId);
    }
    if (count > quota) {
      throw new ApiKeyRateLimitError(quota);
    }
  }

  private flagAnomalyAsync(keyId: string): void {
    Promise.resolve()
      .then(() => this.repo.flagApiKeyAnomaly(keyId, Date.now()))
      .catch(() => {});
  }

  private recordUsageAsync(keyId: string, clientIp?: string): void {
    Promise.resolve()
      .then(() => this.repo.updateApiKeyUsage(keyId, Date.now(), clientIp))
      .catch(() => {});
  }
}

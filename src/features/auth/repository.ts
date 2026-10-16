import type { AuthUserRecord, AuditLogRecord } from './types';
import type { ApiKeyRecord, ClaimedDomainRecord, BlockedDomainRecord, RelationTuple, CustomRoleRecord, WebhookSubscriptionRecord, WebhookDeliveryRecord, BreakGlassSessionRecord } from '../../shared/types/auth.types';

export interface OrganizationRecord {
  id: string;
  name: string;
  slug: string;
  deleted_at?: number;
}

/**
 * AuthRepositoryPort — Application-level persistence contract.
 *
 * Scoped strictly to capabilities that remain in the @observability/auth service
 * after Keycloak migration. Keycloak owns:
 *   - Password credentials & history
 *   - MFA (TOTP / WebAuthn / Passkeys)
 *   - Refresh token families & session revocation
 *   - Email verification
 *   - Social / OAuth identity federation
 *   - SAML 2.0 provider configuration
 *   - SCIM 2.0 directory sync
 *   - OIDC provider / signing key rotation
 *   - Token denylist (short-lived JWTs + Keycloak backchannel logout)
 *   - Magic link passwordless
 */
export interface AuthRepositoryPort {

  // ── Organization & Tenant ────────────────────────────────────────────────
  createOrganization(org: OrganizationRecord, creatorUserId?: string): Promise<void>;
  listOrganizationsByUserId(userId: string): Promise<OrganizationRecord[]>;
  getOrganizationById(orgId: string): Promise<OrganizationRecord | null>;
  updateOrganization(orgId: string, patch: { name?: string; slug?: string }): Promise<void>;
  deleteOrganization(orgId: string): Promise<void>;

  // ── User Management ──────────────────────────────────────────────────────
  createUser(userRecord: AuthUserRecord): Promise<void>;
  createOrganizationAndUser(userRecord: AuthUserRecord): Promise<void>;
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
  exportUserData(userId: string): Promise<{
    user: AuthUserRecord;
    organizations: OrganizationRecord[];
    apiKeys: ApiKeyRecord[];
    auditLogs: AuditLogRecord[];
  } | null>;

  // ── Audit Logs ───────────────────────────────────────────────────────────
  recordAuditLog(logRecord: AuditLogRecord): Promise<void>;
  fetchUserAuditLogs(userId: string, filters?: { event_type?: string; from_ms?: number; to_ms?: number }): Promise<AuditLogRecord[]>;

  // ── API Keys ─────────────────────────────────────────────────────────────
  saveApiKey(keyRecord: ApiKeyRecord): Promise<void>;
  listApiKeysByOrgId(orgId: string): Promise<ApiKeyRecord[]>;
  findApiKeyByHash(hash: string): Promise<ApiKeyRecord | null>;
  revokeApiKey(keyId: string): Promise<void>;
  updateApiKeyUsage(keyId: string, lastUsedAtMs: number, lastUsedIp?: string): Promise<void>;
  updateApiKeyAllowlist(keyId: string, ipAllowlist: readonly string[]): Promise<{ key_id: string; org_id: string; ip_allowlist: string[]; rate_quota_rpm: number | null } | null>;
  findApiKeyMeta(keyId: string): Promise<{ key_id: string; org_id: string; ip_allowlist: string[]; rate_quota_rpm: number | null; anomaly_flag: boolean } | null>;
  flagApiKeyAnomaly(keyId: string, flaggedAtMs: number): Promise<void>;

  // ── Organization Domains ─────────────────────────────────────────────────
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

  // ── Login History (risk scoring) ─────────────────────────────────────────
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

  // ── ReBAC Policy Engine ──────────────────────────────────────────────────
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

  // ── Custom Roles ─────────────────────────────────────────────────────────
  saveCustomRole(role: CustomRoleRecord): Promise<void>;
  findCustomRoleById(id: string, orgId: string): Promise<CustomRoleRecord | null>;
  findCustomRoleByName(name: string, orgId: string): Promise<CustomRoleRecord | null>;
  listCustomRolesByOrgId(orgId: string): Promise<CustomRoleRecord[]>;
  updateCustomRole(id: string, orgId: string, patch: { name?: string; description?: string; permission_mask?: string }): Promise<void>;
  deleteCustomRole(id: string, orgId: string): Promise<void>;
  assignUserCustomRoles(orgId: string, userId: string, roleIds: readonly string[], assignedBy?: string): Promise<void>;
  listUserCustomRoles(orgId: string, userId: string): Promise<CustomRoleRecord[]>;
  recordRoleAuditLog(log: { id: string; org_id: string; actor_user_id: string; action: string; target_role_id: string; target_user_id?: string; previous_mask?: string; new_mask?: string; reason?: string; created_at_ms: number }): Promise<void>;

  // ── Webhooks ─────────────────────────────────────────────────────────────
  saveWebhookSubscription(subscription: WebhookSubscriptionRecord): Promise<void>;
  findWebhookSubscriptionById(id: string, orgId: string): Promise<WebhookSubscriptionRecord | null>;
  listWebhookSubscriptionsByOrgId(orgId: string): Promise<WebhookSubscriptionRecord[]>;
  updateWebhookSubscription(id: string, orgId: string, patch: { target_url?: string; subscribed_events?: readonly string[]; active?: boolean }): Promise<void>;
  deleteWebhookSubscription(id: string, orgId: string): Promise<void>;
  recordWebhookDelivery(delivery: WebhookDeliveryRecord): Promise<void>;
  listWebhookDeliveriesBySubscriptionId(subscriptionId: string, orgId: string): Promise<WebhookDeliveryRecord[]>;

  // ── Field-Level Encryption Keys ──────────────────────────────────────────
  saveUserEncryptionKey(keyRecord: { id: string; user_id: string; org_id: string; kid: string; encrypted_dek: string }): Promise<void>;
  findUserEncryptionKey(userId: string): Promise<{ id: string; user_id: string; org_id: string; kid: string; encrypted_dek: string; dek_status: 'ACTIVE' | 'SHREDDED'; shredded_at?: string } | null>;
  shredUserEncryptionKey(userId: string): Promise<void>;

  // ── Break-Glass Emergency Access ─────────────────────────────────────────
  saveBreakGlassSession(session: BreakGlassSessionRecord): Promise<void>;
  findBreakGlassSessionById(id: string): Promise<BreakGlassSessionRecord | null>;
  findBreakGlassSessionByHash(tokenHash: string): Promise<BreakGlassSessionRecord | null>;
  listActiveBreakGlassSessions(orgId?: string): Promise<BreakGlassSessionRecord[]>;
  terminateBreakGlassSession(id: string, terminatedBy: string, reason: string, terminatedAt: string): Promise<void>;

  // ── Honeytokens ──────────────────────────────────────────────────────────
  saveHoneytoken(honeytoken: {
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
  }): Promise<void>;
  findHoneytokenByHash(tokenHash: string): Promise<{
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
  } | null>;
  recordHoneytokenTrip(id: string, metadata: { ip: string; userAgent: string; timestampMs: number }): Promise<void>;
  listHoneytokensByOrgId(orgId: string): Promise<Array<{
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
  }>>;
  revokeHoneytoken(id: string, orgId: string): Promise<void>;

  // ── WORM Audit Archive ───────────────────────────────────────────────────
  fetchAuditLogsForWormSealing(fromMs: number, toMs: number): Promise<AuditLogRecord[]>;
  saveWormAuditArchive(archive: {
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
  }): Promise<void>;
  findWormAuditArchiveById(id: string): Promise<{
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
  } | null>;
  listWormAuditArchives(): Promise<Array<{
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
  }>>;

  // ── Transactional Outbox ──────────────────────────────────────────────────
  insertOutboxEvent(event: {
    id: string;
    topic: string;
    eventName: string;
    partitionKey: string;
    payload: Record<string, unknown>;
    headers?: Record<string, string>;
  }): Promise<void>;
}

/**
 * @file user-management.service.ts
 * @description Domain Service for User Directory Administration, Invitations, RBAC Role Mutation, and Account Blocking.
 *
 * OVERALL ALGORITHM:
 * 1. User query & profile: Normalize user/org identifier and return user record or throw ValidationError.
 * 2. User invitation & provisioning: Normalize inputs -> check email uniqueness with early throw ->
 *    generate random temporary password and Argon2id hash -> persist user record in organization ->
 *    dispatch invitation email via NotificationDomainService asynchronously.
 * 3. RBAC mutation: Validate inputs, update roles and granular permission arrays in repository.
 * 4. Account lifecycle: Expose administrative block, unblock, and soft-delete operations.
 */

import type { AuthRepositoryPort } from '../repository';
import type {
  AuthUserRecord,
  UpdateUserProfileInput,
  InviteUserInput,
  UpdateUserRoleInput,
  UpdateUserPermissionsInput,
  CreateUserInput,
} from '../types';
import {
  UpdateUserProfileInputSchema,
  InviteUserInputSchema,
  UpdateUserRoleInputSchema,
  UpdateUserPermissionsInputSchema,
  CreateUserInputSchema,
} from '../schema/auth.schema';
import { UserAlreadyExistsError, ValidationError } from '../../../shared/errors/auth.errors';
import { hashPassword } from '../../../shared/utils/argon2.util';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { normalizeString } from '../../../shared/utils/string.util';
import type { NotificationDomainService } from './notification.service';
import type { UserDsarExportPayload } from '../../../shared/types/auth.types';
import { withSpan } from '../../../infra/tracing/tracer';
import { SpanStatusCode } from '@chief-strategist-j/shared-infra';
import { AUTH_CONFIG } from '../../../config/env.config';
import {
  generateUserDek,
  encryptUserDek,
  encryptEnvelope,
  computeBlindIndex,
} from '../../../shared/utils/envelope-encryption.util';

import { randomUUID } from 'crypto';
import type { AuthEventProducer } from '../../../shared/messaging/producers/auth-event.producer';
import { AUTH_KAFKA_TOPICS } from '../../../shared/messaging/topics/auth-topics';

export class UserManagementDomainService {
  constructor(
    private readonly repo: AuthRepositoryPort,
    private readonly notificationService?: NotificationDomainService,
    private readonly eventProducer?: AuthEventProducer,
  ) {}

  async listUsers(orgId: string): Promise<AuthUserRecord[]> {
    const normalizedOrgId = normalizeString(orgId);
    return this.repo.listUsersByOrgId(normalizedOrgId);
  }

  async getUserById(userId: string): Promise<AuthUserRecord> {
    const normalizedUserId = normalizeString(userId);
    const user = await this.repo.findUserById(normalizedUserId);
    if (!user) throw new ValidationError('User not found');
    return user;
  }

  async getMyProfile(userId: string): Promise<AuthUserRecord> {
    return this.getUserById(userId);
  }

  async updateMyProfile(userId: string, input: UpdateUserProfileInput): Promise<AuthUserRecord> {
    const normalizedUserId = normalizeString(userId);
    const validated = UpdateUserProfileInputSchema.parse(input);
    await this.repo.updateUserProfile(normalizedUserId, validated);
    return this.getUserById(normalizedUserId);
  }

  async inviteUser(input: InviteUserInput, orgId: string, orgName: string): Promise<AuthUserRecord> {
    const validated = InviteUserInputSchema.parse(input);
    const email = normalizeString(validated.email, 'lower');
    const normalizedOrgId = normalizeString(orgId);
    const normalizedOrgName = normalizeString(orgName);

    const existingUser = await this.repo.findUserByEmail(email);
    if (existingUser) {
      throw new UserAlreadyExistsError(email);
    }

    const tempPassword = `Tmp_${Math.random().toString(36).substring(2, 10)}!1A`;
    const passwordHash = await hashPassword(tempPassword);
    const userId = `usr_${Math.random().toString(36).substring(2, 9)}`;
    const masterKey = {
      kid: AUTH_CONFIG.encryption.masterKeyId,
      key: Buffer.from(AUTH_CONFIG.encryption.masterKey, 'hex'),
    };
    const userDek = generateUserDek();
    const encryptedUserDek = encryptUserDek(userDek, masterKey);
    const blindIndex = computeBlindIndex(email, AUTH_CONFIG.encryption.blindIndexKey);
    const emailEncrypted = encryptEnvelope(email, masterKey, { orgId: normalizedOrgId, fieldName: 'email' });
    const name = normalizeString(validated.name);
    const nameEncrypted = encryptEnvelope(name, masterKey, { orgId: normalizedOrgId, fieldName: 'name' });
    userDek.fill(0);

    const userRecord: AuthUserRecord = {
      id: userId,
      email,
      password_hash: passwordHash,
      name,
      org_id: normalizedOrgId,
      org_name: normalizedOrgName,
      role: validated.role ?? AUTH_CONSTANTS.ROLE_MEMBER,
      blocked: false,
      user_permissions: Array.isArray(validated.permissions) ? [...validated.permissions] : [],
      name_encrypted: nameEncrypted,
      email_encrypted: emailEncrypted,
      email_blind_index: blindIndex,
    };

    await this.repo.createUser(userRecord);
    if (typeof (this.repo as any).recordPasswordHistory === 'function') {
      await (this.repo as any).recordPasswordHistory(userId, passwordHash);
    }
    await this.repo.saveUserEncryptionKey({
      id: `ukey_${Math.random().toString(36).substring(2, 9)}`,
      user_id: userId,
      org_id: normalizedOrgId,
      kid: masterKey.kid,
      encrypted_dek: encryptedUserDek,
    });

    if (this.notificationService) {
      Promise.resolve()
        .then(() => this.notificationService!.sendUserInviteEmail(email, validated.name, normalizedOrgName, tempPassword))
        .catch(() => {});
    }

    return userRecord;
  }

  async updateUserRole(userId: string, input: UpdateUserRoleInput): Promise<void> {
    const normalizedUserId = normalizeString(userId);
    const validated = UpdateUserRoleInputSchema.parse(input);
    await this.repo.updateUserRole(normalizedUserId, validated.role);
  }

  async getUserPermissions(userId: string): Promise<string[]> {
    const user = await this.getUserById(userId);
    return Array.isArray(user.user_permissions) ? user.user_permissions : [];
  }

  async updateUserPermissions(userId: string, input: UpdateUserPermissionsInput): Promise<void> {
    const normalizedUserId = normalizeString(userId);
    const validated = UpdateUserPermissionsInputSchema.parse(input);
    await this.repo.updateUserPermissions(normalizedUserId, validated.permissions);
  }

  async createUser(input: CreateUserInput): Promise<AuthUserRecord> {
    const validated = CreateUserInputSchema.parse(input);
    const email = normalizeString(validated.email, 'lower');
    const normalizedOrgId = normalizeString(validated.org_id);

    const existingUser = await this.repo.findUserByEmail(email);
    if (existingUser) {
      throw new UserAlreadyExistsError(email);
    }

    const passwordHash = await hashPassword(validated.password);
    const userId = `usr_${Math.random().toString(36).substring(2, 9)}`;
    const masterKey = {
      kid: AUTH_CONFIG.encryption.masterKeyId,
      key: Buffer.from(AUTH_CONFIG.encryption.masterKey, 'hex'),
    };
    const userDek = generateUserDek();
    const encryptedUserDek = encryptUserDek(userDek, masterKey);
    const blindIndex = computeBlindIndex(email, AUTH_CONFIG.encryption.blindIndexKey);
    const emailEncrypted = encryptEnvelope(email, masterKey, { orgId: normalizedOrgId, fieldName: 'email' });
    const name = normalizeString(validated.name);
    const nameEncrypted = encryptEnvelope(name, masterKey, { orgId: normalizedOrgId, fieldName: 'name' });
    userDek.fill(0);

    const userRecord: AuthUserRecord = {
      id: userId,
      email,
      password_hash: passwordHash,
      name,
      org_id: normalizedOrgId,
      org_name: '',
      role: validated.role ?? AUTH_CONSTANTS.ROLE_MEMBER,
      blocked: false,
      user_permissions: Array.isArray(validated.permissions) ? [...validated.permissions] : [],
      name_encrypted: nameEncrypted,
      email_encrypted: emailEncrypted,
      email_blind_index: blindIndex,
    };

    await this.repo.createUser(userRecord);
    if (typeof (this.repo as any).recordPasswordHistory === 'function') {
      await (this.repo as any).recordPasswordHistory(userId, passwordHash);
    }
    await this.repo.saveUserEncryptionKey({
      id: `ukey_${Math.random().toString(36).substring(2, 9)}`,
      user_id: userId,
      org_id: normalizedOrgId,
      kid: masterKey.kid,
      encrypted_dek: encryptedUserDek,
    });
    return userRecord;
  }

  async blockUser(userId: string, blockedBy?: string): Promise<void> {
    const normalizedUserId = normalizeString(userId);
    const existing = await this.repo.findUserById(normalizedUserId);
    await this.repo.blockUser(normalizedUserId);
    const orgId = existing?.org_id ?? 'unknown_org';
    const payload = { userId: normalizedUserId, orgId, blockedBy, timestamp: new Date().toISOString() };
    if (typeof this.repo.insertOutboxEvent === 'function') {
      await this.repo.insertOutboxEvent({
        id: `outbox_${randomUUID()}`,
        topic: AUTH_KAFKA_TOPICS.SECURITY_EVENTS,
        eventName: 'USER_BLOCKED',
        partitionKey: normalizedUserId,
        payload,
      }).catch(() => {});
    } else if (this.eventProducer) {
      await this.eventProducer.publishUserBlocked(payload).catch(() => {});
    }
  }

  async unblockUser(userId: string, unblockedBy?: string): Promise<void> {
    const normalizedUserId = normalizeString(userId);
    const existing = await this.repo.findUserById(normalizedUserId);
    await this.repo.unblockUser(normalizedUserId);
    const orgId = existing?.org_id ?? 'unknown_org';
    const payload = { userId: normalizedUserId, orgId, unblockedBy, timestamp: new Date().toISOString() };
    if (typeof this.repo.insertOutboxEvent === 'function') {
      await this.repo.insertOutboxEvent({
        id: `outbox_${randomUUID()}`,
        topic: AUTH_KAFKA_TOPICS.SECURITY_EVENTS,
        eventName: 'USER_UNBLOCKED',
        partitionKey: normalizedUserId,
        payload,
      }).catch(() => {});
    } else if (this.eventProducer) {
      await this.eventProducer.publishUserUnblocked(payload).catch(() => {});
    }
  }

  async deleteUser(userId: string, deletedBy?: string): Promise<void> {
    const normalizedUserId = normalizeString(userId);
    const existing = await this.repo.findUserById(normalizedUserId);
    await this.repo.shredUserEncryptionKey(normalizedUserId);
    await this.repo.deleteUser(normalizedUserId);
    const orgId = existing?.org_id ?? 'unknown_org';
    const payload = { userId: normalizedUserId, orgId, deletedBy, timestamp: new Date().toISOString() };
    if (typeof this.repo.insertOutboxEvent === 'function') {
      await this.repo.insertOutboxEvent({
        id: `outbox_${randomUUID()}`,
        topic: AUTH_KAFKA_TOPICS.SECURITY_EVENTS,
        eventName: 'USER_DELETED',
        partitionKey: normalizedUserId,
        payload,
      }).catch(() => {});
    } else if (this.eventProducer) {
      await this.eventProducer.publishUserDeleted(payload).catch(() => {});
    }
  }

  async shredUserPii(userId: string): Promise<{ success: boolean; shreddedAt: string }> {
    const normalizedUserId = normalizeString(userId);
    await this.repo.shredUserEncryptionKey(normalizedUserId);
    await this.repo.deleteUser(normalizedUserId);
    const shreddedAt = new Date().toISOString();
    const payload = { userId: normalizedUserId, shreddedAt, timestamp: shreddedAt };
    if (typeof this.repo.insertOutboxEvent === 'function') {
      await this.repo.insertOutboxEvent({
        id: `outbox_${randomUUID()}`,
        topic: AUTH_KAFKA_TOPICS.SECURITY_EVENTS,
        eventName: 'USER_PII_SHREDDED',
        partitionKey: normalizedUserId,
        payload,
      }).catch(() => {});
    } else if (this.eventProducer) {
      await this.eventProducer.publishUserPiiShredded(payload).catch(() => {});
    }
    return {
      success: true,
      shreddedAt,
    };
  }

  async exportUserData(userId: string): Promise<UserDsarExportPayload> {
    const normalizedUserId = normalizeString(userId);
    return withSpan('UserManagementDomainService.exportUserData', async (span) => {
      span.setAttribute('user.id', normalizedUserId);
      span.setAttribute('gdpr.standard', 'Article_15');

      const raw = await this.repo.exportUserData(normalizedUserId);
      if (!raw || !raw.user) {
        throw new ValidationError('User not found');
      }

      const nowIso = new Date().toISOString();
      const mfaEnrolledAt = raw.user.mfa_enrolled_at_ms
        ? new Date(raw.user.mfa_enrolled_at_ms).toISOString()
        : null;

      const payload: UserDsarExportPayload = {
        export_metadata: {
          format_version: '1.0',
          compliance_standard: 'GDPR_Article_15',
          exported_at: nowIso,
          data_subject_id: raw.user.id,
        },
        profile: {
          id: raw.user.id,
          email: raw.user.email,
          name: raw.user.name,
          role: raw.user.role,
          email_verified: Boolean(raw.user.email_verified),
          mfa_enabled: Boolean(raw.user.mfa_enabled),
          mfa_enrolled_at: mfaEnrolledAt,
          permissions: Array.isArray(raw.user.user_permissions) ? [...raw.user.user_permissions] : [],
        },
        organizations: raw.organizations.map((org) => ({
          id: org.id,
          name: org.name,
          slug: org.slug,
          role: raw.user.role,
        })),
        api_keys: raw.apiKeys.map((key) => ({
          key_id: key.key_id,
          name: key.name,
          key_type: key.key_type,
          created_at: new Date(key.created_at_ms).toISOString(),
          last_used_at: key.last_used_at_ms ? new Date(key.last_used_at_ms).toISOString() : null,
          last_used_ip: key.last_used_ip ?? null,
        })),
        audit_logs: raw.auditLogs.map((log) => ({
          id: log.id,
          event_type: log.event_type,
          ip_address: log.ip_address,
          timestamp: new Date(log.timestamp_ms).toISOString(),
        })),
      };

      span.setAttribute('export.orgs_count', payload.organizations.length);
      span.setAttribute('export.keys_count', payload.api_keys.length);
      span.setAttribute('export.logs_count', payload.audit_logs.length);
      span.setStatus({ code: SpanStatusCode.OK });

      return payload;
    });
  }
}

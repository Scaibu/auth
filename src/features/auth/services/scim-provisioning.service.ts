import { createHash } from 'crypto';
import type { AuthRepositoryPort } from '../repository';
import type { CreateScimUserInput, CreateScimGroupInput, ScimUserRecord, ScimGroupRecord, ScimListResponse, ScimPatchRequest } from '../ports/scim-repository.port';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { ValidationError, NotFoundError, UnauthorizedError, ConflictError } from '../../../shared/errors/auth.errors';
import { withSpan } from '../../../infra/tracing/tracer';

export class ScimProvisioningService {
  constructor(private readonly repo: AuthRepositoryPort) {}

  async authenticateScimBearer(tokenHeader?: string): Promise<string> {
    return withSpan('ScimProvisioningService.authenticateScimBearer', async () => {
      if (!tokenHeader || !tokenHeader.startsWith('Bearer ')) {
        throw new UnauthorizedError('Missing or invalid SCIM Bearer token');
      }
      const rawToken = tokenHeader.substring(7).trim();
      const tokenHash = createHash(AUTH_CONSTANTS.CRYPTO.ALGORITHM_SHA256).update(rawToken).digest(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX);
      const record = await this.repo.findScimTokenByHash(tokenHash);
      if (!record || record.status !== 'ACTIVE' || (record.expires_at_ms && record.expires_at_ms < Date.now())) {
        throw new UnauthorizedError('SCIM Bearer token is invalid, revoked, or expired');
      }
      return record.org_id;
    });
  }

  async getServiceProviderConfig(): Promise<Record<string, unknown>> {
    return {
      schemas: [AUTH_CONSTANTS.SCIM.SCHEMA_SERVICE_PROVIDER_CONFIG],
      patch: { supported: true },
      bulk: { supported: false },
      filter: { supported: true, maxResults: AUTH_CONSTANTS.SCIM.DEFAULT_PAGE_SIZE },
      changePassword: { supported: false },
      sort: { supported: false },
      etag: { supported: false },
      authenticationSchemes: [
        {
          name: 'OAuth Bearer Token',
          description: 'Authentication via SCIM Bearer Token',
          specUri: 'http://www.rfc-editor.org/info/rfc6750',
          type: 'oauthbearertoken',
          primary: true,
        },
      ],
    };
  }

  async createUser(orgId: string, input: CreateScimUserInput): Promise<ScimUserRecord> {
    return withSpan('ScimProvisioningService.createUser', async () => {
      const email = input.userName || input.emails?.[0]?.value;
      if (!email) {
        throw new ValidationError('SCIM userName or email is required');
      }
      const existing = await this.repo.findUserByEmail(email);
      if (existing) {
        throw new ConflictError(`User with email ${email} already exists`);
      }

      const now = Date.now();
      const userId = `usr_${now}_${Math.random().toString(36).substring(2, 9)}`;
      const rawName = input.name?.formatted || `${input.name?.givenName || ''} ${input.name?.familyName || ''}`.trim() || email.split('@')[0] || 'SCIM User';
      const name: string = rawName.length > 0 ? rawName : 'SCIM User';

      await this.repo.createUser({
        id: userId,
        email,
        password_hash: `${AUTH_CONSTANTS.OAUTH.DISABLED_PASSWORD_PREFIX}${now}`,
        name,
        org_id: orgId,
        org_name: 'SCIM Organization',
        role: AUTH_CONSTANTS.ROLE_MEMBER,
        blocked: input.active === false,
        user_permissions: [AUTH_CONSTANTS.PERMISSION_METRICS_READ],
      });

      if (input.externalId) {
        await this.repo.saveExternalMapping(orgId, 'user', userId, input.externalId);
      }

      await this.repo.recordAuditLog({
        id: `aud_${now}_${Math.random().toString(36).substring(2, 9)}`,
        user_id: userId,
        org_id: orgId,
        event_type: AUTH_CONSTANTS.AUDIT_EVENT_SCIM_USER_PROVISIONED,
        ip_address: '127.0.0.1',
        user_agent: 'SCIM-2.0-Client',
        timestamp_ms: now,
      });

      return this.mapToScimUser(userId, email, name, input.active !== false, input.externalId);
    });
  }

  async getUser(orgId: string, userId: string): Promise<ScimUserRecord> {
    return withSpan('ScimProvisioningService.getUser', async () => {
      const user = await this.repo.findUserById(userId);
      if (!user || user.org_id !== orgId) {
        throw new NotFoundError(`SCIM User ${userId} not found`);
      }
      return this.mapToScimUser(user.id, user.email, user.name, !user.blocked);
    });
  }

  async listUsers(orgId: string, filter?: string, startIndex = 1, count = 100): Promise<ScimListResponse<ScimUserRecord>> {
    return withSpan('ScimProvisioningService.listUsers', async () => {
      const users = await this.repo.listUsersByOrgId(orgId);
      let filtered = users;
      if (filter) {
        const match = filter.match(/userName eq "(.*?)"/i);
        if (match && match[1]) {
          const target = match[1].toLowerCase();
          filtered = users.filter((u) => u.email.toLowerCase() === target);
        }
      }
      const page = filtered.slice(startIndex - 1, (startIndex - 1) + count);
      const resources = page.map((u) => this.mapToScimUser(u.id, u.email, u.name, !u.blocked));
      return {
        schemas: [AUTH_CONSTANTS.SCIM.SCHEMA_LIST_RESPONSE],
        totalResults: filtered.length,
        startIndex,
        itemsPerPage: resources.length,
        Resources: resources,
      };
    });
  }

  async patchUser(orgId: string, userId: string, patch: ScimPatchRequest): Promise<ScimUserRecord> {
    return withSpan('ScimProvisioningService.patchUser', async () => {
      const user = await this.repo.findUserById(userId);
      if (!user || user.org_id !== orgId) {
        throw new NotFoundError(`SCIM User ${userId} not found`);
      }

      for (const op of patch.Operations) {
        const path = op.path?.toLowerCase();
        if (path === 'active' || (typeof op.value === 'object' && op.value !== null && 'active' in (op.value as any))) {
          const isActive = path === 'active' ? Boolean(op.value) : Boolean((op.value as any).active);
          if (!isActive) {
            await this.repo.blockUser(userId);
            await this.repo.recordAuditLog({
              id: `aud_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
              user_id: userId,
              org_id: orgId,
              event_type: AUTH_CONSTANTS.AUDIT_EVENT_SCIM_USER_DEPROVISIONED,
              ip_address: '127.0.0.1',
              user_agent: 'SCIM-2.0-Client',
              timestamp_ms: Date.now(),
            });
          } else {
            await this.repo.unblockUser(userId);
          }
        }
      }

      const updated = await this.repo.findUserById(userId);
      return this.mapToScimUser(updated!.id, updated!.email, updated!.name, !updated!.blocked);
    });
  }

  async deleteUser(orgId: string, userId: string): Promise<void> {
    return withSpan('ScimProvisioningService.deleteUser', async () => {
      const user = await this.repo.findUserById(userId);
      if (!user || user.org_id !== orgId) {
        throw new NotFoundError(`SCIM User ${userId} not found`);
      }
      await this.repo.deleteUser(userId);
      await this.repo.recordAuditLog({
        id: `aud_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
        user_id: userId,
        org_id: orgId,
        event_type: AUTH_CONSTANTS.AUDIT_EVENT_SCIM_USER_DEPROVISIONED,
        ip_address: '127.0.0.1',
        user_agent: 'SCIM-2.0-Client',
        timestamp_ms: Date.now(),
      });
    });
  }

  async createGroup(orgId: string, input: CreateScimGroupInput): Promise<ScimGroupRecord> {
    return withSpan('ScimProvisioningService.createGroup', async () => {
      if (!input.displayName) {
        throw new ValidationError('SCIM Group displayName is required');
      }
      const groupId = `grp_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
      await this.repo.saveScimGroup(orgId, {
        id: groupId,
        displayName: input.displayName,
        externalId: input.externalId,
      });

      if (input.members && input.members.length > 0) {
        for (const member of input.members) {
          await this.repo.addScimGroupMember(groupId, member.value);
        }
      }

      const created = await this.repo.findScimGroupById(orgId, groupId);
      return created!;
    });
  }

  async getGroup(orgId: string, groupId: string): Promise<ScimGroupRecord> {
    return withSpan('ScimProvisioningService.getGroup', async () => {
      const group = await this.repo.findScimGroupById(orgId, groupId);
      if (!group) {
        throw new NotFoundError(`SCIM Group ${groupId} not found`);
      }
      return group;
    });
  }

  async listGroups(orgId: string, filter?: string, startIndex = 1, count = 100): Promise<ScimListResponse<ScimGroupRecord>> {
    return withSpan('ScimProvisioningService.listGroups', async () => {
      const res = await this.repo.listScimGroups(orgId, filter, startIndex, count);
      return {
        schemas: [AUTH_CONSTANTS.SCIM.SCHEMA_LIST_RESPONSE],
        totalResults: res.total,
        startIndex,
        itemsPerPage: res.groups.length,
        Resources: res.groups,
      };
    });
  }

  async patchGroup(orgId: string, groupId: string, patch: ScimPatchRequest): Promise<ScimGroupRecord> {
    return withSpan('ScimProvisioningService.patchGroup', async () => {
      const group = await this.repo.findScimGroupById(orgId, groupId);
      if (!group) {
        throw new NotFoundError(`SCIM Group ${groupId} not found`);
      }

      for (const op of patch.Operations) {
        const opType = op.op.toLowerCase();
        if (opType === 'add' && Array.isArray(op.value)) {
          for (const m of op.value) {
            if (m.value) await this.repo.addScimGroupMember(groupId, m.value);
          }
        } else if (opType === 'remove') {
          if (op.path && op.path.startsWith('members[value eq "')) {
            const userId = op.path.substring('members[value eq "'.length, op.path.length - 2);
            await this.repo.removeScimGroupMember(groupId, userId);
          }
        }
      }

      return (await this.repo.findScimGroupById(orgId, groupId))!;
    });
  }

  async deleteGroup(orgId: string, groupId: string): Promise<void> {
    return withSpan('ScimProvisioningService.deleteGroup', async () => {
      const group = await this.repo.findScimGroupById(orgId, groupId);
      if (!group) {
        throw new NotFoundError(`SCIM Group ${groupId} not found`);
      }
      await this.repo.deleteScimGroup(orgId, groupId);
    });
  }

  private mapToScimUser(id: string, email: string, name: string, active: boolean, externalId?: string): ScimUserRecord {
    const parts = name.split(' ');
    const givenName = parts[0] || name;
    const familyName = parts.slice(1).join(' ') || parts[0];
    const nowIso = new Date().toISOString();

    return {
      id,
      externalId,
      userName: email,
      name: {
        formatted: name,
        familyName,
        givenName,
      },
      displayName: name,
      emails: [{ value: email, primary: true, type: 'work' }],
      active,
      meta: {
        resourceType: 'User',
        created: nowIso,
        lastModified: nowIso,
        location: `/scim/v2/Users/${id}`,
      },
    };
  }
}

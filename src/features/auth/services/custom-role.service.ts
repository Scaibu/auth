import * as crypto from 'crypto';
import type { AuthRepositoryPort } from '../repository';
import type { CustomRoleRecord, PermissionEvaluationResult } from '../../../shared/types/auth.types';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { ValidationError, NotFoundError, ConflictError, ForbiddenError } from '../../../shared/errors/auth.errors';
import { withSpan } from '../../../infra/tracing/tracer';

export class CustomRoleService {
  constructor(private readonly repository: AuthRepositoryPort) {}

  async createCustomRole(
    orgId: string,
    params: Readonly<{
      name: string;
      description?: string;
      permission_mask: string;
    }>,
    creatorUserId?: string
  ): Promise<CustomRoleRecord> {
    return withSpan('CustomRoleService.createCustomRole', async (span: any) => {
      span?.setAttribute('auth.org_id', orgId);
      span?.setAttribute('auth.role_name', params.name);

      const trimmedName = params.name.trim();
      if (trimmedName.length === 0) {
        throw new ValidationError('Role name cannot be empty');
      }

      const existing = await this.repository.findCustomRoleByName(trimmedName, orgId);
      if (existing) {
        throw new ConflictError(`Custom role '${trimmedName}' already exists in this organization`);
      }

      const maskBigInt = BigInt(params.permission_mask);
      if (maskBigInt < 0n) {
        throw new ValidationError('Permission mask cannot be negative');
      }

      const id = `crole_${crypto.randomUUID()}`;
      const publicId = `pub_${id}`;
      const now = Date.now();

      const record: CustomRoleRecord = {
        id,
        public_id: publicId,
        org_id: orgId,
        name: trimmedName,
        description: params.description ?? '',
        permission_mask: maskBigInt.toString(),
        is_system_role: false,
        version: 1,
        created_at_ms: now,
        updated_at_ms: now,
      };

      await this.repository.saveCustomRole(record);

      await this.repository.recordRoleAuditLog({
        id: `raudit_${crypto.randomUUID()}`,
        org_id: orgId,
        actor_user_id: creatorUserId ?? 'system',
        action: 'ROLE_CREATED',
        target_role_id: id,
        new_mask: maskBigInt.toString(),
        reason: 'Initial role provisioning',
        created_at_ms: now,
      });

      return record;
    });
  }

  async getCustomRoleById(id: string, orgId: string): Promise<CustomRoleRecord> {
    return withSpan('CustomRoleService.getCustomRoleById', async () => {
      const role = await this.repository.findCustomRoleById(id, orgId);
      if (!role) {
        throw new NotFoundError(`Custom role '${id}' not found`);
      }
      return role;
    });
  }

  async listCustomRoles(orgId: string): Promise<CustomRoleRecord[]> {
    return withSpan('CustomRoleService.listCustomRoles', async () => {
      return this.repository.listCustomRolesByOrgId(orgId);
    });
  }

  async updateCustomRole(
    id: string,
    orgId: string,
    patch: Readonly<{
      name?: string;
      description?: string;
      permission_mask?: string;
    }>,
    actorUserId?: string
  ): Promise<CustomRoleRecord> {
    return withSpan('CustomRoleService.updateCustomRole', async (span: any) => {
      span?.setAttribute('auth.org_id', orgId);
      span?.setAttribute('auth.role_id', id);
      const existing = await this.repository.findCustomRoleById(id, orgId);
      if (!existing) {
        throw new NotFoundError(`Custom role '${id}' not found`);
      }
      if (existing.is_system_role) {
        throw new ForbiddenError('System roles cannot be modified');
      }

      if (patch.name !== undefined) {
        const trimmed = patch.name.trim();
        if (trimmed.length === 0) {
          throw new ValidationError('Role name cannot be empty');
        }
        if (trimmed !== existing.name) {
          const duplicate = await this.repository.findCustomRoleByName(trimmed, orgId);
          if (duplicate) {
            throw new ConflictError(`Custom role '${trimmed}' already exists`);
          }
        }
      }

      let parsedMask: string | undefined;
      if (patch.permission_mask !== undefined) {
        const maskBigInt = BigInt(patch.permission_mask);
        if (maskBigInt < 0n) {
          throw new ValidationError('Permission mask cannot be negative');
        }
        parsedMask = maskBigInt.toString();
      }

      await this.repository.updateCustomRole(id, orgId, {
        name: patch.name?.trim(),
        description: patch.description,
        permission_mask: parsedMask,
      });

      const updated = await this.repository.findCustomRoleById(id, orgId);
      if (!updated) {
        throw new NotFoundError(`Custom role '${id}' not found after update`);
      }

      await this.repository.recordRoleAuditLog({
        id: `raudit_${crypto.randomUUID()}`,
        org_id: orgId,
        actor_user_id: actorUserId ?? 'system',
        action: 'ROLE_UPDATED',
        target_role_id: id,
        previous_mask: existing.permission_mask,
        new_mask: updated.permission_mask,
        created_at_ms: Date.now(),
      });

      return updated;
    });
  }

  async deleteCustomRole(id: string, orgId: string, actorUserId?: string): Promise<void> {
    return withSpan('CustomRoleService.deleteCustomRole', async () => {
      const existing = await this.repository.findCustomRoleById(id, orgId);
      if (!existing) {
        throw new NotFoundError(`Custom role '${id}' not found`);
      }
      if (existing.is_system_role) {
        throw new ForbiddenError('System roles cannot be deleted');
      }

      await this.repository.deleteCustomRole(id, orgId);

      await this.repository.recordRoleAuditLog({
        id: `raudit_${crypto.randomUUID()}`,
        org_id: orgId,
        actor_user_id: actorUserId ?? 'system',
        action: 'ROLE_DELETED',
        target_role_id: id,
        previous_mask: existing.permission_mask,
        created_at_ms: Date.now(),
      });
    });
  }

  async assignUserRoles(
    orgId: string,
    userId: string,
    roleIds: readonly string[],
    actorUserId?: string
  ): Promise<void> {
    return withSpan('CustomRoleService.assignUserRoles', async (span: any) => {
      span?.setAttribute('auth.org_id', orgId);
      span?.setAttribute('auth.user_id', userId);

      for (const roleId of roleIds) {
        const role = await this.repository.findCustomRoleById(roleId, orgId);
        if (!role) {
          throw new NotFoundError(`Custom role '${roleId}' does not exist in organization`);
        }
      }

      await this.repository.assignUserCustomRoles(orgId, userId, roleIds, actorUserId);

      for (const roleId of roleIds) {
        await this.repository.recordRoleAuditLog({
          id: `raudit_${crypto.randomUUID()}`,
          org_id: orgId,
          actor_user_id: actorUserId ?? 'system',
          action: 'ROLE_ASSIGNED',
          target_role_id: roleId,
          target_user_id: userId,
          reason: 'Custom role binding',
          created_at_ms: Date.now(),
        });
      }
    });
  }

  async getUserEffectivePermissionMask(orgId: string, userId: string): Promise<bigint> {
    const roles = await this.repository.listUserCustomRoles(orgId, userId);
    if (roles.length === 0) {
      const user = await this.repository.findUserById(userId);
      if (user && user.role === 'admin') {
        return (1n << 37n) - 1n;
      }
      return 0n;
    }

    let effectiveMask = 0n;
    for (const role of roles) {
      effectiveMask = effectiveMask | BigInt(role.permission_mask);
    }
    return effectiveMask;
  }

  async evaluateUserPermissions(
    orgId: string,
    userId: string,
    requiredPermissions: readonly string[]
  ): Promise<PermissionEvaluationResult> {
    return withSpan('CustomRoleService.evaluateUserPermissions', async (span: any) => {
      span?.setAttribute('auth.org_id', orgId);
      span?.setAttribute('auth.user_id', userId);

      let requiredMask = 0n;
      const bitmaskRegistry = AUTH_CONSTANTS.PERMISSIONS_BITMASK as Record<string, string>;

      for (const perm of requiredPermissions) {
        const maskStr = bitmaskRegistry[perm];
        if (!maskStr) {
          throw new ValidationError(`Unknown permission key '${perm}'`);
        }
        requiredMask = requiredMask | BigInt(maskStr);
      }

      const effectiveMask = await this.getUserEffectivePermissionMask(orgId, userId);
      const isGranted = (effectiveMask & requiredMask) === requiredMask;
      const missingBits = requiredMask & (~effectiveMask);

      span?.setAttribute('auth.granted', isGranted);
      span?.setAttribute('auth.effective_mask', effectiveMask.toString());

      return {
        granted: isGranted,
        effective_mask: effectiveMask.toString(),
        missing_bits: missingBits.toString(),
        evaluated_permissions: [...requiredPermissions],
      };
    });
  }
}

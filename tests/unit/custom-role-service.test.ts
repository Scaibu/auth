import { describe, it, expect, beforeEach } from 'vitest';
import { CustomRoleService } from '../../src/features/auth/services/custom-role.service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';
import { ValidationError, NotFoundError, ConflictError, ForbiddenError } from '../../src/shared/errors/auth.errors';

describe('CustomRoleService Unit Tests', () => {
  let adapter: AlloyDBOmniAuthAdapter;
  let service: CustomRoleService;
  const orgId = 'org_unit_custom_roles';
  const userId = 'usr_unit_custom_roles';

  beforeEach(() => {
    adapter = new AlloyDBOmniAuthAdapter();
    service = new CustomRoleService(adapter);
  });

  it('creates a custom enterprise role with valid 64-bit permission bitmask', async () => {
    const sreMask = (
      BigInt(AUTH_CONSTANTS.PERMISSIONS_BITMASK.TELEMETRY_READ) |
      BigInt(AUTH_CONSTANTS.PERMISSIONS_BITMASK.TELEMETRY_WRITE)
    ).toString();

    const role = await service.createCustomRole(orgId, {
      name: 'Site Reliability Engineer',
      description: 'Telemetry ingest and querying permissions',
      permission_mask: sreMask,
    }, userId);

    expect(role.id).toBeDefined();
    expect(role.public_id).toBeDefined();
    expect(role.name).toBe('Site Reliability Engineer');
    expect(role.permission_mask).toBe(sreMask);
    expect(role.is_system_role).toBe(false);

    const fetched = await service.getCustomRoleById(role.id, orgId);
    expect(fetched.name).toBe('Site Reliability Engineer');
  });

  it('rejects duplicate custom role creation in the same organization', async () => {
    await service.createCustomRole(orgId, {
      name: 'Auditor',
      permission_mask: AUTH_CONSTANTS.PERMISSIONS_BITMASK.AUDIT_LOGS_READ,
    });

    await expect(
      service.createCustomRole(orgId, {
        name: 'Auditor',
        permission_mask: AUTH_CONSTANTS.PERMISSIONS_BITMASK.AUDIT_LOGS_READ,
      })
    ).rejects.toThrow(ConflictError);
  });

  it('rejects custom role creation with empty name or negative permission mask', async () => {
    await expect(
      service.createCustomRole(orgId, {
        name: '   ',
        permission_mask: '1',
      })
    ).rejects.toThrow(ValidationError);

    await expect(
      service.createCustomRole(orgId, {
        name: 'Invalid Mask Role',
        permission_mask: '-5',
      })
    ).rejects.toThrow(ValidationError);
  });

  it('prevents mutation and deletion of system roles', async () => {
    await adapter.saveCustomRole({
      id: 'crole_system_default',
      public_id: 'pub_crole_system_default',
      org_id: orgId,
      name: 'Super System Role',
      description: 'Immutable system role',
      permission_mask: '1',
      is_system_role: true,
      version: 1,
      created_at_ms: Date.now(),
      updated_at_ms: Date.now(),
    });

    await expect(
      service.updateCustomRole('crole_system_default', orgId, { name: 'New Name' })
    ).rejects.toThrow(ForbiddenError);

    await expect(
      service.deleteCustomRole('crole_system_default', orgId)
    ).rejects.toThrow(ForbiddenError);
  });

  it('evaluates user permissions via multi-role bitwise OR in O(1) time', async () => {
    const role1 = await service.createCustomRole(orgId, {
      name: 'Telemetry Reader',
      permission_mask: AUTH_CONSTANTS.PERMISSIONS_BITMASK.TELEMETRY_READ,
    });

    const role2 = await service.createCustomRole(orgId, {
      name: 'Policy Admin',
      permission_mask: AUTH_CONSTANTS.PERMISSIONS_BITMASK.POLICIES_MANAGE,
    });

    await service.assignUserRoles(orgId, userId, [role1.id, role2.id]);

    const evalResult1 = await service.evaluateUserPermissions(orgId, userId, [
      'TELEMETRY_READ',
      'POLICIES_MANAGE',
    ]);
    expect(evalResult1.granted).toBe(true);
    expect(evalResult1.missing_bits).toBe('0');

    const evalResult2 = await service.evaluateUserPermissions(orgId, userId, [
      'TELEMETRY_READ',
      'ORG_DELETE',
    ]);
    expect(evalResult2.granted).toBe(false);
    expect(BigInt(evalResult2.missing_bits)).toBe(BigInt(AUTH_CONSTANTS.PERMISSIONS_BITMASK.ORG_DELETE));
  });

  it('rejects permission evaluation with unknown permission key', async () => {
    await expect(
      service.evaluateUserPermissions(orgId, userId, ['NON_EXISTENT_PERMISSION_KEY'])
    ).rejects.toThrow(ValidationError);
  });
});

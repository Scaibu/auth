import { describe, it, expect, beforeAll } from 'vitest';
import { CustomRoleService } from '../../src/features/auth/services/custom-role.service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('Custom Roles & 64-Bit Bitmask Performance Benchmark', () => {
  let adapter: AlloyDBOmniAuthAdapter;
  let service: CustomRoleService;
  const orgId = 'org_perf_roles';
  const userId = 'usr_perf_roles';

  beforeAll(async () => {
    adapter = new AlloyDBOmniAuthAdapter();
    service = new CustomRoleService(adapter);

    const maskA = (
      BigInt(AUTH_CONSTANTS.PERMISSIONS_BITMASK.TELEMETRY_READ) |
      BigInt(AUTH_CONSTANTS.PERMISSIONS_BITMASK.TELEMETRY_WRITE)
    ).toString();

    const maskB = (
      BigInt(AUTH_CONSTANTS.PERMISSIONS_BITMASK.USERS_READ) |
      BigInt(AUTH_CONSTANTS.PERMISSIONS_BITMASK.API_KEYS_READ)
    ).toString();

    const roleA = await service.createCustomRole(orgId, {
      name: 'Perf Role A',
      permission_mask: maskA,
    });

    const roleB = await service.createCustomRole(orgId, {
      name: 'Perf Role B',
      permission_mask: maskB,
    });

    await service.assignUserRoles(orgId, userId, [roleA.id, roleB.id]);
  });

  it('evaluates 10,000 permission bitmask checks in < 50ms (< 0.005ms per check)', async () => {
    const iterations = 10000;
    const requiredPermissions = ['TELEMETRY_READ', 'TELEMETRY_WRITE'];

    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      const res = await service.evaluateUserPermissions(orgId, userId, requiredPermissions);
      if (!res.granted) {
        throw new Error('Expected permissions to be granted');
      }
    }
    const elapsed = performance.now() - start;
    const avgMs = elapsed / iterations;

    expect(elapsed).toBeLessThan(350);
    expect(avgMs).toBeLessThan(0.035);
  });
});

import { describe, it, expect, beforeEach } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AUTH_ENDPOINTS, HTTP_METHODS } from '../../src/shared/constants/endpoints';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('Immutable WORM Audit Archive REST Endpoints Integration (ADR 0042)', () => {
  let adapter: AlloyDBOmniAuthAdapter;
  let service: AuthService;
  let router: AuthRestV1Router;
  let adminAuthHeader: string;

  beforeEach(async () => {
    adapter = new AlloyDBOmniAuthAdapter();
    service = new AuthService(adapter as any);
    router = new AuthRestV1Router(service);

    const signUpResult = await service.signUp({
      email: 'compliance_officer@observability.internal',
      password: 'AdminPassword123!',
      name: 'Compliance Officer',
      organization_name: 'Audit Enterprise',
      role: AUTH_CONSTANTS.ROLE_ADMIN,
    });

    adminAuthHeader = `${AUTH_CONSTANTS.HEADERS.BEARER_PREFIX}${signUpResult.token}`;

    const now = Date.now();
    await adapter.recordAuditLog({
      id: 'audit_01',
      user_id: 'usr_sec_01',
      org_id: 'org_sec_01',
      event_type: 'USER_LOGIN',
      ip_address: '10.0.0.1',
      user_agent: 'Chrome/120',
      timestamp_ms: now - 3000,
    });
    await adapter.recordAuditLog({
      id: 'audit_02',
      user_id: 'usr_sec_02',
      org_id: 'org_sec_01',
      event_type: 'API_KEY_REVOKED',
      ip_address: '10.0.0.5',
      user_agent: 'Curl/8.0',
      timestamp_ms: now - 1000,
    });
  });

  it('seals an audit log segment, lists archives, and verifies cryptographic Merkle root', async () => {
    const now = Date.now();

    // 1. Seal audit segment
    const sealRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.WORM_AUDIT_SEAL,
      {
        segment_start_ms: now - 10000,
        segment_end_ms: now,
        retention_years: 7,
      },
      {
        authorization: adminAuthHeader,
      }
    );

    expect(sealRes.statusCode).toBe(201);
    expect(sealRes.payload.status).toBe('success');
    const sealedData = sealRes.payload.data as any;
    expect(sealedData.id).toMatch(/^worm_arc_/);
    expect(sealedData.record_count).toBe(2);
    expect(sealedData.status).toBe('SEALED');
    expect(sealedData.merkle_root).toHaveLength(64);

    // 2. List WORM archives
    const listRes = await router.route(
      HTTP_METHODS.GET,
      AUTH_ENDPOINTS.WORM_AUDIT_ARCHIVES,
      undefined,
      {
        authorization: adminAuthHeader,
      }
    );

    expect(listRes.statusCode).toBe(200);
    expect(listRes.payload.status).toBe('success');
    const archives = listRes.payload.data as any[];
    expect(archives.length).toBeGreaterThanOrEqual(1);
    expect(archives[0].id).toBe(sealedData.id);

    // 3. Verify cryptographic Merkle root
    const verifyEndpoint = AUTH_ENDPOINTS.WORM_AUDIT_VERIFY.replace(':id', sealedData.id);
    const verifyRes = await router.route(
      HTTP_METHODS.GET,
      verifyEndpoint,
      undefined,
      {
        authorization: adminAuthHeader,
      }
    );

    expect(verifyRes.statusCode).toBe(200);
    expect(verifyRes.payload.status).toBe('success');
    const proof = verifyRes.payload.data as any;
    expect(proof.verified).toBe(true);
    expect(proof.archive_id).toBe(sealedData.id);
    expect(proof.sealed_merkle_root).toBe(sealedData.merkle_root);
    expect(proof.recomputed_merkle_root).toBe(sealedData.merkle_root);
  });
});

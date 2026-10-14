import { describe, it, expect, beforeEach } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { MockBreachedPasswordAdapter } from '../../src/infra/adapters/security/mock-pwned-passwords.adapter';

describe('GDPR Article 15 DSAR JSON Export Scenarios', () => {
  let router: AuthRestV1Router;
  let service: AuthService;
  let repo: AlloyDBOmniAuthAdapter;
  let userToken: string;
  let userEmail: string;

  beforeEach(async () => {
    repo = new AlloyDBOmniAuthAdapter();
    const mockBreach = new MockBreachedPasswordAdapter([]);
    service = new AuthService(
      repo,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      mockBreach
    );
    router = new AuthRestV1Router(service);

    userEmail = `dsar_user_${Date.now()}@enterprise.com`;
    const signUpRes = await router.route('POST', '/api/v1/auth/sign-up', {
      email: userEmail,
      password: 'StrongDsarPass123!',
      name: 'Alice Export',
      organization_name: 'Dsar Corp',
    });
    userToken = (signUpRes.payload.data as any).token;

    const orgId = (signUpRes.payload.data as any).user.org_id;

    // Sign in to produce an audit log record
    await router.route('POST', '/api/v1/auth/sign-in', {
      email: userEmail,
      password: 'StrongDsarPass123!',
    });

    // Create an API key under this account to ensure multi-entity export
    await router.route(
      'POST',
      '/api/v1/auth/api-keys',
      {
        name: 'Export Test Key',
        org_id: orgId,
        key_type: 'general',
        permissions: ['traces:read'],
      },
      {
        authorization: `Bearer ${userToken}`,
      }
    );
  });

  it('rejects export request when not authenticated (401 Unauthorized)', async () => {
    const res = await router.route('GET', '/api/v1/auth/users/me/export');
    expect(res.statusCode).toBe(401);
    expect(res.payload.status).toBe('error');
    expect(res.payload.error?.code).toBe('UNAUTHORIZED');
  });

  it('exports comprehensive GDPR Article 15 JSON archive with zero credential leakage', async () => {
    const res = await router.route(
      'GET',
      '/api/v1/auth/users/me/export',
      undefined,
      {
        authorization: `Bearer ${userToken}`,
      }
    );

    expect(res.statusCode).toBe(200);
    expect(res.payload.status).toBe('success');

    const data = res.payload.data as any;
    expect(data).toHaveProperty('export_metadata');
    expect(data.export_metadata.compliance_standard).toBe('GDPR_Article_15');
    expect(data.export_metadata.format_version).toBe('1.0');

    // Profile check
    expect(data.profile.email).toBe(userEmail);
    expect(data.profile.name).toBe('Alice Export');
    expect(data.profile).not.toHaveProperty('password_hash');
    expect(data.profile).not.toHaveProperty('mfa_secret');

    // Organizations check
    expect(Array.isArray(data.organizations)).toBe(true);
    expect(data.organizations.length).toBeGreaterThanOrEqual(1);
    expect(data.organizations[0].name).toBe('Dsar Corp');

    // API Keys check
    expect(Array.isArray(data.api_keys)).toBe(true);
    expect(data.api_keys.length).toBeGreaterThanOrEqual(1);
    expect(data.api_keys[0].name).toBe('Export Test Key');
    expect(data.api_keys[0]).not.toHaveProperty('key_hash');

    // Audit logs check
    expect(Array.isArray(data.audit_logs)).toBe(true);
    expect(data.audit_logs.length).toBeGreaterThanOrEqual(1);
  });

  it('rejects export request when bearer token is malformed or forged (401 Unauthorized)', async () => {
    const res = await router.route(
      'GET',
      '/api/v1/auth/users/me/export',
      undefined,
      {
        authorization: 'Bearer forged.invalid.token.signature',
      }
    );
    expect(res.statusCode).toBe(401);
    expect(res.payload.status).toBe('error');
    expect(res.payload.error?.code).toBe('TOKEN_EXPIRED');
  });

  it('rejects export with 400 Validation Error if the authenticated subject does not exist in repository', async () => {
    const fakeToken = (await router.route('POST', '/api/v1/auth/sign-in', {
      email: userEmail,
      password: 'StrongDsarPass123!',
    })).payload.data as any;

    await repo.deleteUser(fakeToken.user.id);

    const res = await router.route(
      'GET',
      '/api/v1/auth/users/me/export',
      undefined,
      {
        authorization: `Bearer ${userToken}`,
      }
    );
    expect(res.statusCode).toBe(400);
    expect(res.payload.status).toBe('error');
    expect(res.payload.error?.code).toBe('VALIDATION_ERROR');
  });

  it('accurately exports multi-organization associations for the requesting data subject', async () => {
    const secondOrgEmail = `multi_org_${Date.now()}@enterprise.com`;
    const secondSignUp = await router.route('POST', '/api/v1/auth/sign-up', {
      email: secondOrgEmail,
      password: 'StrongDsarPass123!',
      name: 'Bob MultiOrg',
      organization_name: 'Primary Org',
    });
    const bobToken = (secondSignUp.payload.data as any).token;

    await router.route(
      'POST',
      '/api/v1/auth/organizations',
      {
        name: 'Secondary Affiliated Corp',
        slug: `secondary-${Date.now()}`,
      },
      {
        authorization: `Bearer ${bobToken}`,
      }
    );

    const res = await router.route(
      'GET',
      '/api/v1/auth/users/me/export',
      undefined,
      {
        authorization: `Bearer ${bobToken}`,
      }
    );

    expect(res.statusCode).toBe(200);
    const data = res.payload.data as any;
    expect(data.organizations.length).toBeGreaterThanOrEqual(2);
    const orgNames = data.organizations.map((o: any) => o.name);
    expect(orgNames).toContain('Primary Org');
    expect(orgNames).toContain('Secondary Affiliated Corp');
  });

  it('enforces strict RFC 3339 UTC ISO 8601 timestamp string formats across all exported entities', async () => {
    const res = await router.route(
      'GET',
      '/api/v1/auth/users/me/export',
      undefined,
      {
        authorization: `Bearer ${userToken}`,
      }
    );

    expect(res.statusCode).toBe(200);
    const data = res.payload.data as any;
    const isoUtcRegex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

    expect(data.export_metadata.exported_at).toMatch(isoUtcRegex);
    expect(data.api_keys[0].created_at).toMatch(isoUtcRegex);
    expect(data.audit_logs[0].timestamp).toMatch(isoUtcRegex);
  });
});

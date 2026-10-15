import { describe, it, expect, beforeAll } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import type { DnsResolverPort } from '../../src/features/auth/ports/dns-resolver.port';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';
import { AUTH_ENDPOINTS, HTTP_METHODS } from '../../src/shared/constants/endpoints';

describe('Domain Claiming & Verified Auto-Join End-to-End API Flow', () => {
  let router: AuthRestV1Router;
  let adminToken: string;
  let corporateOrgId: string;
  const corporateDomain = `enterprise-${Date.now()}.com`;
  const mockDnsRecords = new Map<string, string[][]>();

  beforeAll(async () => {
    const repo = new AlloyDBOmniAuthAdapter();
    const mockDns: DnsResolverPort = {
      resolveTxt: async (hostname: string) => mockDnsRecords.get(hostname) || [],
    };
    const authService = new AuthService(
      repo,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      mockDns,
    );
    router = new AuthRestV1Router(authService);

    const adminSignUp = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: `admin_${Date.now()}@testcorp.com`,
      password: 'AdminPassword123!',
      name: 'Corporate Admin',
      organization_name: 'Acme Global Enterprises',
      role: AUTH_CONSTANTS.ROLE_ADMIN,
    });
    expect(adminSignUp.statusCode).toBe(201);
    adminToken = (adminSignUp.payload.data as any).token;
    corporateOrgId = (adminSignUp.payload.data as any).user.organization_id;
  });

  it('rejects unauthenticated and non-admin blocked domain management', async () => {
    const unauthRes = await router.route(HTTP_METHODS.GET, AUTH_ENDPOINTS.ADMIN_BLOCKED_DOMAINS);
    expect(unauthRes.statusCode).toBe(401);

    const listRes = await router.route(
      HTTP_METHODS.GET,
      AUTH_ENDPOINTS.ADMIN_BLOCKED_DOMAINS,
      undefined,
      { authorization: `Bearer ${adminToken}` },
    );
    expect(listRes.statusCode).toBe(200);
    expect(Array.isArray(listRes.payload.data)).toBe(true);
    const domains = (listRes.payload.data as any[]).map((d) => d.domain_name);
    expect(domains).toContain('gmail.com');
  });

  it('dynamically registers and unblocks domains via Admin API', async () => {
    const customBlocked = `disposable-${Date.now()}.xyz`;

    const addRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.ADMIN_BLOCKED_DOMAINS,
      {
        domain: customBlocked,
        category: AUTH_CONSTANTS.DOMAIN_CLAIM.CATEGORY_DISPOSABLE,
        reason: 'Temporary test disposable domain',
      },
      { authorization: `Bearer ${adminToken}` },
    );
    expect(addRes.statusCode).toBe(201);
    expect((addRes.payload.data as any).domain_name).toBe(customBlocked);

    const claimBlocked = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.DOMAINS,
      { domain: customBlocked },
      { authorization: `Bearer ${adminToken}` },
    );
    expect(claimBlocked.statusCode).toBe(400);

    const removeRes = await router.route(
      HTTP_METHODS.DELETE,
      `/api/v1/auth/admin/blocked-domains/${customBlocked}`,
      undefined,
      { authorization: `Bearer ${adminToken}` },
    );
    expect(removeRes.statusCode).toBe(200);
  });

  it('executes full domain claim, DNS TXT verification, and auto-join routing on registration', async () => {
    const claimRes = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.DOMAINS,
      { domain: corporateDomain, default_role: AUTH_CONSTANTS.ROLE_MEMBER },
      { authorization: `Bearer ${adminToken}` },
    );
    expect(claimRes.statusCode).toBe(201);
    const domainData = claimRes.payload.data as any;
    expect(domainData.domain_name).toBe(corporateDomain);
    expect(domainData.status).toBe(AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_PENDING);

    const preVerifyRes = await router.route(
      HTTP_METHODS.POST,
      `/api/v1/auth/domains/${domainData.domain_id}/verify`,
      undefined,
      { authorization: `Bearer ${adminToken}` },
    );
    expect(preVerifyRes.statusCode).toBe(400);
    expect(preVerifyRes.payload.error?.message).toBe(AUTH_CONSTANTS.ERROR_MESSAGES.DOMAIN_VERIFICATION_FAILED);

    mockDnsRecords.set(
      `${AUTH_CONSTANTS.DOMAIN_CLAIM.CHALLENGE_SUBDOMAIN_PREFIX}.${corporateDomain}`,
      [[domainData.verification_token]],
    );

    const verifyRes = await router.route(
      HTTP_METHODS.POST,
      `/api/v1/auth/domains/${domainData.domain_id}/verify`,
      undefined,
      { authorization: `Bearer ${adminToken}` },
    );
    expect(verifyRes.statusCode).toBe(200);
    expect((verifyRes.payload.data as any).verified).toBe(true);
    expect((verifyRes.payload.data as any).status).toBe(AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_VERIFIED);

    const employeeEmail = `alice@${corporateDomain}`;
    const employeeSignUp = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: employeeEmail,
      password: 'EmployeePassword123!',
      name: 'Alice Employee',
      organization_name: 'Ignored Fallback Org',
    });
    expect(employeeSignUp.statusCode).toBe(201);
    const employeeToken = (employeeSignUp.payload.data as any).token;

    const sessionRes = await router.route(
      HTTP_METHODS.GET,
      AUTH_ENDPOINTS.SESSION,
      undefined,
      { authorization: `Bearer ${employeeToken}` },
    );
    expect(sessionRes.statusCode).toBe(200);
    const sessionData = sessionRes.payload.data as any;
    expect(sessionData.email).toBe(employeeEmail);
    expect(sessionData.organization_id).toBe(corporateOrgId);
  });
});

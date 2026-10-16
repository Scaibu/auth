import { describe, it, expect, beforeEach } from 'vitest';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AuthService } from '../../src/features/auth/service';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import type { DnsResolverPort } from '../../src/features/auth/ports/dns-resolver.port';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';
import { createToken } from '../../src/shared/utils/jwt.util';

class MockDnsAdapter implements DnsResolverPort {
  private readonly records = new Map<string, string[][]>();

  setTxt(hostname: string, txtValues: string[]): void {
    this.records.set(hostname, txtValues.map((v) => [v]));
  }

  clear(): void {
    this.records.clear();
  }

  async resolveTxt(hostname: string): Promise<string[][]> {
    return this.records.get(hostname) || [];
  }
}

describe('Organization Domain Claiming & Verified Auto-Join (ADR 0021)', () => {
  let repo: AlloyDBOmniAuthAdapter;
  let mockDns: MockDnsAdapter;
  let service: AuthService;
  let router: AuthRestV1Router;

  const adminEmail = AUTH_CONSTANTS.DEFAULT_ADMIN_EMAIL;
  let adminToken: string;
  let adminHeaders: Record<string, string>;

  beforeEach(async () => {
    repo = new AlloyDBOmniAuthAdapter();
    mockDns = new MockDnsAdapter();
    service = new AuthService(
      repo,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      mockDns,
    );
    router = new AuthRestV1Router(service);

    const adminUser = await repo.findUserByEmail(adminEmail);
    adminToken = createToken(adminUser!.id, adminUser!.email, {
      org_id: adminUser!.org_id,
      org_name: adminUser!.org_name,
      role: adminUser!.role,
    });
    adminHeaders = { authorization: `Bearer ${adminToken}` };
  });

  describe('Domain Claim Initiation (POST /api/v1/auth/domains)', () => {
    it('should generate a pending claim with DNS challenge token', async () => {
      const res = await router.route('POST', '/api/v1/auth/domains', {
        domain: 'blute.co.in',
        default_role: 'member',
      }, adminHeaders);

      expect(res.statusCode).toBe(201);
      expect(res.payload.status).toBe('success');

      const data = res.payload.data as any;
      expect(data.domain_name).toBe('blute.co.in');
      expect(data.status).toBe('PENDING_VERIFICATION');
      expect(data.verification_record).toBe('_llmobs-challenge.blute.co.in');
      expect(data.verification_token).toContain('llmobs-verification=');
      expect(data.default_role).toBe('member');
    });

    it('should reject public freemail domains with HTTP 400', async () => {
      const res = await router.route('POST', '/api/v1/auth/domains', {
        domain: 'gmail.com',
      }, adminHeaders);

      expect(res.statusCode).toBe(400);
      expect(res.payload.message).toContain('Public email domains cannot be claimed');
    });

    it('should reject duplicate claim for the same domain with HTTP 409', async () => {
      await router.route('POST', '/api/v1/auth/domains', {
        domain: 'blute.co.in',
      }, adminHeaders);

      const res = await router.route('POST', '/api/v1/auth/domains', {
        domain: 'blute.co.in',
      }, adminHeaders);

      expect(res.statusCode).toBe(409);
    });
  });

  describe('DNS Verification (POST /api/v1/auth/domains/:domainId/verify)', () => {
    it('should fail verification if DNS TXT record is missing', async () => {
      const claimRes = await router.route('POST', '/api/v1/auth/domains', {
        domain: 'enterprise.org',
      }, adminHeaders);
      const { domain_id } = claimRes.payload.data as any;

      const verifyRes = await router.route('POST', `/api/v1/auth/domains/${domain_id}/verify`, undefined, adminHeaders);
      expect(verifyRes.statusCode).toBe(400);
      expect(verifyRes.payload.message).toContain('DNS TXT verification challenge record not found');
    });

    it('should verify domain when matching DNS TXT record is present', async () => {
      const claimRes = await router.route('POST', '/api/v1/auth/domains', {
        domain: 'enterprise.org',
      }, adminHeaders);
      const { domain_id, verification_record, verification_token } = claimRes.payload.data as any;

      mockDns.setTxt(verification_record, [verification_token]);

      const verifyRes = await router.route('POST', `/api/v1/auth/domains/${domain_id}/verify`, undefined, adminHeaders);
      expect(verifyRes.statusCode).toBe(200);
      expect(verifyRes.payload.status).toBe('success');
      expect((verifyRes.payload.data as any).status).toBe('VERIFIED');
    });
  });



  describe('Domain Settings & Lifecycle Management', () => {
    it('should list and delete claimed domain', async () => {
      const claimRes = await router.route('POST', '/api/v1/auth/domains', {
        domain: 'staging.blute.co.in',
      }, adminHeaders);
      const { domain_id } = claimRes.payload.data as any;

      const listRes = await router.route('GET', '/api/v1/auth/domains', undefined, adminHeaders);
      expect(listRes.statusCode).toBe(200);
      expect((listRes.payload.data as any[]).length).toBe(1);

      const delRes = await router.route('DELETE', `/api/v1/auth/domains/${domain_id}`, undefined, adminHeaders);
      expect(delRes.statusCode).toBe(200);

      const listAfter = await router.route('GET', '/api/v1/auth/domains', undefined, adminHeaders);
      expect((listAfter.payload.data as any[]).length).toBe(0);
    });
  });
});

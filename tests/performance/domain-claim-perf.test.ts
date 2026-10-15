import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { RealPostgresAuthAdapter } from '../../src/infra/adapters/postgres/real-postgres-auth.adapter';
import { DomainClaimService } from '../../src/features/auth/services/domain-claim.service';
import type { DnsResolverPort } from '../../src/features/auth/ports/dns-resolver.port';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('Domain Claiming & Blocked Domains Performance Benchmark', () => {
  let adapter: RealPostgresAuthAdapter;
  let domainClaimService: DomainClaimService;
  const corporateDomain = `perf-corp-${Date.now()}.com`;

  beforeAll(async () => {
    adapter = new RealPostgresAuthAdapter();
    const mockDns: DnsResolverPort = {
      resolveTxt: async () => [],
    };
    domainClaimService = new DomainClaimService(adapter, mockDns);

    const orgId = `org_perf_${Date.now()}`;
    await adapter.createOrganization({ id: orgId, name: `Perf Corp ${Date.now()}`, slug: `perf-${Date.now()}` });
    await adapter.saveClaimedDomain({
      id: `dom_perf_${Date.now()}`,
      org_id: orgId,
      domain_name: corporateDomain,
      status: AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_VERIFIED,
      verification_token: 'llmobs-verification=perf123',
      verification_method: 'DNS_TXT',
      default_role: 'member',
      auto_join_enabled: true,
      created_at_ms: Date.now(),
      verified_at_ms: Date.now(),
    });
  });

  afterAll(async () => {
    await adapter.close();
  });

  it('performs indexed blocked domain checks in < 4.0ms per query under sustained load', async () => {
    const iterations = 500;
    const start = performance.now();

    for (let i = 0; i < iterations; i++) {
      const res = await adapter.findBlockedDomain('gmail.com');
      expect(res).not.toBeNull();
      expect(res?.category).toBe('FREEMAIL');
    }

    const elapsedMs = performance.now() - start;
    const avgLatencyMs = elapsedMs / iterations;

    expect(avgLatencyMs).toBeLessThan(4.0);
  });

  it('resolves verified domain lookup for user emails in < 4.5ms per query under sustained load', async () => {
    const iterations = 500;
    const email = `engineer@${corporateDomain}`;
    const start = performance.now();

    for (let i = 0; i < iterations; i++) {
      const res = await domainClaimService.findVerifiedDomainForEmail(email);
      expect(res).not.toBeNull();
      expect(res?.domain_name).toBe(corporateDomain);
    }

    const elapsedMs = performance.now() - start;
    const avgLatencyMs = elapsedMs / iterations;

    expect(avgLatencyMs).toBeLessThan(4.5);
  });
});


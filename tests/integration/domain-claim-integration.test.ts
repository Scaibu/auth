import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { RealPostgresAuthAdapter } from '../../src/infra/adapters/postgres/real-postgres-auth.adapter';
import { DomainClaimService } from '../../src/features/auth/services/domain-claim.service';
import type { DnsResolverPort } from '../../src/features/auth/ports/dns-resolver.port';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('Domain Claiming & Dynamic Blocked Domains Integration Tests (Real AlloyDB)', () => {
  let adapter: RealPostgresAuthAdapter;
  let dnsMock: DnsResolverPort;
  let domainClaimService: DomainClaimService;
  const mockDnsTxtRecords = new Map<string, string[]>();

  beforeAll(async () => {
    adapter = new RealPostgresAuthAdapter();
    dnsMock = {
      resolveTxt: async (hostname: string) => mockDnsTxtRecords.get(hostname) || [],
    };
    domainClaimService = new DomainClaimService(adapter, dnsMock);
  });

  afterAll(async () => {
    await adapter.close();
  });

  it('rejects claiming dynamically blocked freemail domains from database', async () => {
    const orgId = `org_test_${Date.now()}`;
    await adapter.createOrganization({ id: orgId, name: `Integration Test Org ${Date.now()}`, slug: `org-${Date.now()}` });

    await expect(domainClaimService.claimDomain(orgId, { domain: 'gmail.com' }))
      .rejects.toThrow(AUTH_CONSTANTS.ERROR_MESSAGES.DOMAIN_PUBLIC_FREEMAIL_FORBIDDEN);
  });

  it('allows dynamic registration and unblocking of domains in auth_blocked_domains table', async () => {
    const customBlockedDomain = `temp-disposable-${Date.now()}.com`;
    const now = Date.now();

    await adapter.saveBlockedDomain({
      domain_name: customBlockedDomain,
      category: AUTH_CONSTANTS.DOMAIN_CLAIM.CATEGORY_DISPOSABLE,
      reason: 'Temporary test disposable email domain',
      created_at_ms: now,
      updated_at_ms: now,
    });

    const found = await adapter.findBlockedDomain(customBlockedDomain);
    expect(found).not.toBeNull();
    expect(found?.domain_name).toBe(customBlockedDomain);
    expect(found?.category).toBe(AUTH_CONSTANTS.DOMAIN_CLAIM.CATEGORY_DISPOSABLE);

    const orgId = `org_test_${Date.now()}`;
    await expect(domainClaimService.claimDomain(orgId, { domain: customBlockedDomain }))
      .rejects.toThrow(AUTH_CONSTANTS.ERROR_MESSAGES.DOMAIN_PUBLIC_FREEMAIL_FORBIDDEN);

    await adapter.deleteBlockedDomain(customBlockedDomain);
    const unblocked = await adapter.findBlockedDomain(customBlockedDomain);
    expect(unblocked).toBeNull();
  });

  it('persists, queries, verifies and deletes claimed domain in real database', async () => {
    const orgId = `org_integ_${Date.now()}`;
    await adapter.createOrganization({ id: orgId, name: `Claim Test Corp ${Date.now()}`, slug: `claim-${Date.now()}` });
    const corporateDomain = `acme-corp-${Date.now()}.co.in`;

    const claimRes = await domainClaimService.claimDomain(orgId, { domain: corporateDomain });
    expect(claimRes.domain_name).toBe(corporateDomain);
    expect(claimRes.status).toBe(AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_PENDING);

    const saved = await adapter.findClaimedDomainById(claimRes.domain_id);
    expect(saved).not.toBeNull();
    expect(saved?.status).toBe(AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_PENDING);

    mockDnsTxtRecords.set(
      `${AUTH_CONSTANTS.DOMAIN_CLAIM.CHALLENGE_SUBDOMAIN_PREFIX}.${corporateDomain}`,
      [claimRes.verification_token],
    );

    const verifyRes = await domainClaimService.verifyDomain(claimRes.domain_id, orgId);
    expect(verifyRes.verified).toBe(true);
    expect(verifyRes.status).toBe(AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_VERIFIED);

    const verifiedRecord = await adapter.findClaimedDomainById(claimRes.domain_id);
    expect(verifiedRecord?.status).toBe(AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_VERIFIED);
    expect(verifiedRecord?.verified_at_ms).toBeGreaterThan(0);

    const autoJoinTarget = await domainClaimService.findVerifiedDomainForEmail(`engineer@${corporateDomain}`);
    expect(autoJoinTarget).not.toBeNull();
    expect(autoJoinTarget?.org_id).toBe(orgId);

    await domainClaimService.deleteClaimedDomain(claimRes.domain_id, orgId);
    const deletedRecord = await adapter.findClaimedDomainById(claimRes.domain_id);
    expect(deletedRecord).toBeNull();
  });
});

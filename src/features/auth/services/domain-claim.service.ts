import { randomBytes } from 'crypto';
import type { AuthRepositoryPort } from '../repository';
import type { DnsResolverPort } from '../ports/dns-resolver.port';
import type { ClaimedDomainRecord } from '../../../shared/types/auth.types';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { BadRequestError, ConflictError, NotFoundError } from '../../../shared/errors/auth.errors';
import { withSpan } from '../../../infra/tracing/tracer';

export interface ClaimDomainInput {
  domain: string;
  default_role?: string;
}

export interface ClaimDomainResult {
  domain_id: string;
  domain_name: string;
  status: string;
  verification_record: string;
  verification_token: string;
  verification_method: string;
  default_role: string;
  auto_join_enabled: boolean;
}

export interface VerifyDomainResult {
  domain_id: string;
  domain_name: string;
  status: string;
  verified: boolean;
  message: string;
}

export class DomainClaimService {
  constructor(
    private readonly repository: AuthRepositoryPort,
    private readonly dnsResolver: DnsResolverPort,
  ) {}

  public normalizeDomain(rawDomain: string): string {
    const cleaned = rawDomain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!cleaned || !cleaned.includes('.')) {
      throw new BadRequestError('Invalid domain format');
    }
    return cleaned;
  }

  public async checkDnsChallenge(domainName: string, expectedToken: string): Promise<boolean> {
    const challengeHostname = `${AUTH_CONSTANTS.DOMAIN_CLAIM.CHALLENGE_SUBDOMAIN_PREFIX}.${domainName}`;
    const records = await this.dnsResolver.resolveTxt(challengeHostname);
    const flatRecords = records.flat();
    return flatRecords.some((txt) => txt.trim() === expectedToken.trim());
  }

  public async claimDomain(orgId: string, input: ClaimDomainInput): Promise<ClaimDomainResult> {
    return withSpan('DomainClaimService.claimDomain', async (span) => {
      span.setAttribute('tenant.org_id', orgId);
      const domainName = this.normalizeDomain(input.domain);
      span.setAttribute('domain.name', domainName);

      const isBlocked = await this.repository.findBlockedDomain(domainName);
      if (isBlocked) {
        throw new BadRequestError(AUTH_CONSTANTS.ERROR_MESSAGES.DOMAIN_PUBLIC_FREEMAIL_FORBIDDEN);
      }

      const existing = await this.repository.findClaimedDomainByName(domainName);
      if (existing) {
        if (existing.org_id === orgId) {
          throw new ConflictError('Domain is already registered for this organization');
        }
        throw new ConflictError(AUTH_CONSTANTS.ERROR_MESSAGES.DOMAIN_ALREADY_CLAIMED);
      }

      const domainId = `dom_${randomBytes(8).toString(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX)}`;
      const verificationToken = `${AUTH_CONSTANTS.DOMAIN_CLAIM.VERIFICATION_PREFIX}${randomBytes(16).toString(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX)}`;
      const now = Date.now();
      const defaultRole = input.default_role || AUTH_CONSTANTS.ROLE_MEMBER;

      const record: ClaimedDomainRecord = {
        id: domainId,
        org_id: orgId,
        domain_name: domainName,
        status: AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_PENDING,
        verification_token: verificationToken,
        verification_method: AUTH_CONSTANTS.DOMAIN_CLAIM.METHOD_DNS_TXT,
        default_role: defaultRole,
        auto_join_enabled: true,
        created_at_ms: now,
      };

      await this.repository.saveClaimedDomain(record);

      await this.repository.recordAuditLog({
        id: `aud_${now}_${randomBytes(4).toString(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX)}`,
        user_id: orgId,
        org_id: orgId,
        event_type: AUTH_CONSTANTS.AUDIT_EVENT_DOMAIN_CLAIMED,
        ip_address: '127.0.0.1',
        user_agent: 'DomainClaimService',
        timestamp_ms: now,
      });

      return {
        domain_id: domainId,
        domain_name: domainName,
        status: record.status,
        verification_record: `${AUTH_CONSTANTS.DOMAIN_CLAIM.CHALLENGE_SUBDOMAIN_PREFIX}.${domainName}`,
        verification_token: verificationToken,
        verification_method: record.verification_method,
        default_role: record.default_role,
        auto_join_enabled: record.auto_join_enabled,
      };
    });
  }

  public async verifyDomain(domainId: string, orgId: string): Promise<VerifyDomainResult> {
    return withSpan('DomainClaimService.verifyDomain', async (span) => {
      span.setAttribute('domain.id', domainId);
      span.setAttribute('tenant.org_id', orgId);

      const domain = await this.repository.findClaimedDomainById(domainId);
      if (!domain || domain.org_id !== orgId) {
        throw new NotFoundError(AUTH_CONSTANTS.ERROR_MESSAGES.DOMAIN_NOT_FOUND);
      }

      if (domain.status === AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_VERIFIED) {
        return {
          domain_id: domain.id,
          domain_name: domain.domain_name,
          status: domain.status,
          verified: true,
          message: AUTH_CONSTANTS.ERROR_MESSAGES.DOMAIN_ALREADY_VERIFIED,
        };
      }

      const matched = await this.checkDnsChallenge(domain.domain_name, domain.verification_token);
      if (!matched) {
        throw new BadRequestError(AUTH_CONSTANTS.ERROR_MESSAGES.DOMAIN_VERIFICATION_FAILED);
      }


      const now = Date.now();
      await this.repository.updateClaimedDomainStatus(domain.id, AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_VERIFIED, now);

      await this.repository.recordAuditLog({
        id: `aud_${now}_${randomBytes(4).toString(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX)}`,
        user_id: orgId,
        org_id: orgId,
        event_type: AUTH_CONSTANTS.AUDIT_EVENT_DOMAIN_VERIFIED,
        ip_address: '127.0.0.1',
        user_agent: 'DomainClaimService',
        timestamp_ms: now,
      });

      return {
        domain_id: domain.id,
        domain_name: domain.domain_name,
        status: AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_VERIFIED,
        verified: true,
        message: 'Domain successfully verified and activated for enterprise auto-join',
      };
    });
  }

  public async listClaimedDomains(orgId: string): Promise<ClaimedDomainRecord[]> {
    return withSpan('DomainClaimService.listClaimedDomains', async (span) => {
      span.setAttribute('tenant.org_id', orgId);
      return this.repository.listClaimedDomainsByOrgId(orgId);
    });
  }

  public async updateDomainSettings(
    domainId: string,
    orgId: string,
    patch: { auto_join_enabled?: boolean; default_role?: string },
  ): Promise<ClaimedDomainRecord> {
    return withSpan('DomainClaimService.updateDomainSettings', async (span) => {
      span.setAttribute('domain.id', domainId);
      const domain = await this.repository.findClaimedDomainById(domainId);
      if (!domain || domain.org_id !== orgId) {
        throw new NotFoundError(AUTH_CONSTANTS.ERROR_MESSAGES.DOMAIN_NOT_FOUND);
      }

      const autoJoin = patch.auto_join_enabled !== undefined ? patch.auto_join_enabled : domain.auto_join_enabled;
      const defaultRole = patch.default_role || domain.default_role;

      await this.repository.updateClaimedDomainSettings(domainId, autoJoin, defaultRole);
      const updated = await this.repository.findClaimedDomainById(domainId);
      return updated!;
    });
  }

  public async deleteClaimedDomain(domainId: string, orgId: string): Promise<void> {
    return withSpan('DomainClaimService.deleteClaimedDomain', async (span) => {
      span.setAttribute('domain.id', domainId);
      const domain = await this.repository.findClaimedDomainById(domainId);
      if (!domain || domain.org_id !== orgId) {
        throw new NotFoundError(AUTH_CONSTANTS.ERROR_MESSAGES.DOMAIN_NOT_FOUND);
      }

      await this.repository.deleteClaimedDomain(domainId);

      const now = Date.now();
      await this.repository.recordAuditLog({
        id: `aud_${now}_${randomBytes(4).toString(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX)}`,
        user_id: orgId,
        org_id: orgId,
        event_type: AUTH_CONSTANTS.AUDIT_EVENT_DOMAIN_REVOKED,
        ip_address: '127.0.0.1',
        user_agent: 'DomainClaimService',
        timestamp_ms: now,
      });
    });
  }

  public async findVerifiedDomainForEmail(email: string): Promise<ClaimedDomainRecord | null> {
    const parts = email.split('@');
    if (parts.length !== 2) return null;
    const domainName = parts[1]!.toLowerCase().trim();

    const isBlocked = await this.repository.findBlockedDomain(domainName);
    if (isBlocked) {
      return null;
    }

    const domain = await this.repository.findClaimedDomainByName(domainName);
    if (!domain || domain.status !== AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_VERIFIED || !domain.auto_join_enabled) {
      return null;
    }
    return domain;
  }
}

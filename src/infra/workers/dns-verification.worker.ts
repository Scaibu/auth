/**
 * @file dns-verification.worker.ts
 * @description Autonomous background worker for continuous DNS challenge verification and grace-period expiration.
 *
 * OVERALL ALGORITHM:
 * 1. Initialize with DomainClaimService or AuthRepositoryPort and DnsResolverPort, adhering strictly to single-responsibility and dependency inversion.
 * 2. Schedule periodic verification cycles using unreferenced interval timers.
 * 3. Enforce single-cycle concurrency protection to prevent overlap.
 * 4. Query repository for all pending or verified domains.
 * 5. Delegate DNS TXT challenge resolution to centralized DomainClaimService.checkDnsChallenge().
 * 6. Transition pending domains to verified on match.
 * 7. Transition verified domains lacking active challenge records to suspended if past grace period (AUTH_CONSTANTS.DOMAIN_CLAIM.GRACE_PERIOD_MS).
 */

import type { AuthRepositoryPort } from '../../features/auth/repository';
import type { DnsResolverPort } from '../../features/auth/ports/dns-resolver.port';
import { DomainClaimService } from '../../features/auth/services/domain-claim.service';
import { AUTH_CONSTANTS } from '../../shared/constants/auth.constants';
import { withSpan } from '../tracing/tracer';

export interface DnsVerificationWorkerOptions {
  readonly intervalMs?: number;
  readonly enabled?: boolean;
}

export interface DnsVerificationCycleResult {
  readonly checked: number;
  readonly verified: number;
  readonly suspended: number;
}

export class DnsVerificationWorker {
  private timer: NodeJS.Timeout | null = null;
  private isRunningCycle = false;
  private readonly domainClaimService: DomainClaimService;

  constructor(
    private readonly repository: AuthRepositoryPort,
    private readonly dnsResolver: DnsResolverPort,
    private readonly options: DnsVerificationWorkerOptions = {},
    domainClaimService?: DomainClaimService,
  ) {
    this.domainClaimService = domainClaimService ?? new DomainClaimService(this.repository, this.dnsResolver);
  }

  public start(): void {
    if (this.options.enabled === false) return;
    const interval = this.options.intervalMs ?? 5 * 60 * 1000;
    this.timer = setInterval(() => {
      this.executeVerificationCycle().catch(() => {});
    }, interval);
    if (this.timer.unref) this.timer.unref();
  }

  public stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  public async executeVerificationCycle(): Promise<DnsVerificationCycleResult> {
    if (this.isRunningCycle) return { checked: 0, verified: 0, suspended: 0 };
    this.isRunningCycle = true;

    return withSpan('DnsVerificationWorker.executeVerificationCycle', async (span) => {
      let verifiedCount = 0;
      let suspendedCount = 0;

      try {
        const domains = await this.repository.listPendingOrVerifiedDomains();
        span.setAttribute('worker.domains.count', domains.length);

        for (const domain of domains) {
          const matches = await this.domainClaimService.checkDnsChallenge(domain.domain_name, domain.verification_token);
          const now = Date.now();

          if (domain.status === AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_PENDING && matches) {
            await this.repository.updateClaimedDomainStatus(domain.id, AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_VERIFIED, now);
            verifiedCount++;
          } else if (domain.status === AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_VERIFIED && !matches) {
            const lastVerified = domain.verified_at_ms || domain.created_at_ms;
            if (now - lastVerified > AUTH_CONSTANTS.DOMAIN_CLAIM.GRACE_PERIOD_MS) {
              await this.repository.updateClaimedDomainStatus(domain.id, AUTH_CONSTANTS.DOMAIN_CLAIM.STATUS_SUSPENDED);
              suspendedCount++;
            }
          }
        }

        return { checked: domains.length, verified: verifiedCount, suspended: suspendedCount };
      } finally {
        this.isRunningCycle = false;
      }
    });
  }
}

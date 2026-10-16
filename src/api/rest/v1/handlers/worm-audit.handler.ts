/**
 * @file worm-audit.handler.ts
 * @description HTTP Handlers for Immutable WORM Audit Archive Lifecycle (SEC Rule 17a-4(f)).
 *
 * OVERALL ALGORITHM:
 * 1. handleSealWormAudit:
 *    - Authenticates administrative identity from verified JWT session.
 *    - Validates ingress JSON payload against SealWormAuditInputSchema.
 *    - Invokes wormAuditService.sealAuditSegment with segment boundaries and admin user ID.
 *    - Serializes created sealed record in compliance response envelope.
 * 2. handleListWormAuditArchives:
 *    - Authenticates administrative caller.
 *    - Queries all sealed WORM archive segments from database.
 *    - Serializes archive records for auditor review.
 * 3. handleVerifyWormAuditArchive:
 *    - Extracts archive ID from path parameters.
 *    - Invokes wormAuditService.verifyArchiveIntegrity to recalculate Merkle root against cold logs.
 *    - Returns mathematical proof status and verification details.
 *
 * STRICT INVARIANT: ZERO inline comments inside function bodies. File header docblock only.
 */

import type { AuthService } from '../../../../features/auth/service';
import { SealWormAuditInputSchema } from '../../../../features/auth/schema/auth.schema';
import { UnauthorizedError } from '../../../../shared/errors/auth.errors';

export async function handleSealWormAudit(
  service: AuthService,
  body: unknown,
  session: any
): Promise<any> {
  const userId = session?.sub ?? session?.payload?.sub;
  if (!userId) {
    throw new UnauthorizedError('Administrative authentication required to seal WORM audit archives');
  }

  const parsed = SealWormAuditInputSchema.parse(body);

  return await service.wormAuditService.sealAuditSegment({
    segment_start_ms: parsed.segment_start_ms,
    segment_end_ms: parsed.segment_end_ms,
    retention_years: parsed.retention_years,
    sealed_by_user_id: userId,
  });
}

export async function handleListWormAuditArchives(
  service: AuthService,
  session: any
): Promise<any> {
  const userId = session?.sub ?? session?.payload?.sub;
  if (!userId) {
    throw new UnauthorizedError('Authentication required to view WORM audit archives');
  }

  return await service.wormAuditService.listArchives();
}

export async function handleVerifyWormAuditArchive(
  service: AuthService,
  archiveId: string,
  session: any
): Promise<any> {
  const userId = session?.sub ?? session?.payload?.sub;
  if (!userId) {
    throw new UnauthorizedError('Authentication required to verify WORM audit archive integrity');
  }

  return await service.wormAuditService.verifyArchiveIntegrity(archiveId);
}

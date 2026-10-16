import type { AuthService } from '../../../../features/auth/service';
import type { AuthTokenPayload } from '../../../../shared/types/auth.types';
import { UnauthorizedError, BadRequestError } from '../../../../shared/errors/auth.errors';

function isNonEmptyString(val: unknown): val is string {
  return typeof val === 'string' && val.trim().length > 0;
}

export async function handleActivateBreakGlass(
  service: AuthService,
  body: any,
  session?: AuthTokenPayload
): Promise<unknown> {
  const userId = session?.sub;
  const orgId = session?.org?.org_id;

  if (!isNonEmptyString(userId) || !isNonEmptyString(orgId)) {
    throw new UnauthorizedError('Authentication required');
  }

  if (!isNonEmptyString(body?.incident_ticket_id)) {
    throw new BadRequestError('incident_ticket_id is required');
  }
  if (!isNonEmptyString(body?.justification)) {
    throw new BadRequestError('justification is required');
  }

  return service.activateBreakGlass({
    userId,
    orgId,
    incidentTicketId: body.incident_ticket_id,
    justification: body.justification,
    durationMinutes: body.duration_minutes,
    elevatedRole: body.elevated_role,
  });
}

export async function handleTerminateBreakGlass(
  service: AuthService,
  sessionId: string,
  body: any,
  session?: AuthTokenPayload
): Promise<unknown> {
  const userId = session?.sub;
  const orgId = session?.org?.org_id;

  if (!isNonEmptyString(userId) || !isNonEmptyString(orgId)) {
    throw new UnauthorizedError('Authentication required');
  }

  if (!isNonEmptyString(body?.reason)) {
    throw new BadRequestError('reason is required for terminating break-glass session');
  }

  return service.terminateBreakGlass({
    sessionId,
    terminatedBy: userId,
    reason: body.reason,
    orgId,
  });
}

export async function handleListActiveBreakGlassSessions(
  service: AuthService,
  session?: AuthTokenPayload
): Promise<unknown> {
  const orgId = session?.org?.org_id;
  if (!isNonEmptyString(orgId)) {
    throw new UnauthorizedError('Authentication required');
  }

  return service.listActiveBreakGlassSessions(orgId);
}

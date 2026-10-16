/**
 * @file honeytoken.handler.ts
 * @description Ingress REST delivery handlers for Honeytokens & Active Canary Secret Scanning (ADR 0041).
 *
 * EXECUTION ALGORITHM:
 * 1. Validate session token and extract authenticated organization context.
 * 2. Parse and normalize incoming payloads using Zod Ingress schema (CreateHoneytokenInputSchema).
 * 3. Invoke domain HoneytokenService within hexagonal boundaries.
 * 4. Return clean data response envelopes without leaking internal canary metadata.
 */

import type { AuthService } from '../../../../features/auth/service';
import type { AuthTokenPayload } from '../../../../shared/types/auth.types';
import { CreateHoneytokenInputSchema } from '../../../../features/auth/schema/auth.schema';
import { validateSchema } from '../../../../shared/utils/validation.util';
import { UnauthorizedError, ValidationError } from '../../../../shared/errors/auth.errors';

export async function handleCreateHoneytoken(
  service: AuthService,
  body: unknown,
  session: AuthTokenPayload
): Promise<unknown> {
  if (!session?.org?.org_id) {
    throw new UnauthorizedError('Authentication required to provision honeytokens');
  }

  const input = validateSchema(CreateHoneytokenInputSchema, body);
  return service.honeytokenService.createHoneytoken({
    org_id: session.org.org_id,
    name: input.name,
    deployed_location: input.deployed_location,
  });
}

export async function handleListHoneytokens(
  service: AuthService,
  session: AuthTokenPayload
): Promise<unknown> {
  if (!session?.org?.org_id) {
    throw new UnauthorizedError('Authentication required to list honeytokens');
  }

  return service.honeytokenService.listHoneytokens(session.org.org_id);
}

export async function handleRevokeHoneytoken(
  service: AuthService,
  id: string,
  session: AuthTokenPayload
): Promise<unknown> {
  if (!session?.org?.org_id) {
    throw new UnauthorizedError('Authentication required to revoke honeytoken');
  }

  if (!id || id.trim() === '') {
    throw new ValidationError('Valid honeytoken id is required');
  }

  await service.honeytokenService.revokeHoneytoken(id.trim(), session.org.org_id);
  return { revoked: true, id: id.trim() };
}

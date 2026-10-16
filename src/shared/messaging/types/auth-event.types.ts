/**
 * @file auth-event.types.ts
 * @description Strongly-typed payload definitions for all authentication, authorization, and security Kafka events.
 *
 * OVERALL ALGORITHM:
 * 1. Define typed payloads for User & Identity events (sign-up, sign-in, profile, password, email).
 * 2. Define typed payloads for Security & Threat events (block, delete, shred, risk challenge, break-glass, honeytoken).
 * 3. Define typed payloads for Organization & Tenant events (create, update, switch, delete, domain claim).
 * 4. Define typed payloads for Access Control events (API keys, ReBAC relations, custom roles).
 * 5. Define typed payloads for Compliance & WORM audit events.
 *
 * STRICT INVARIANT: ZERO inline comments inside function/type bodies. File header docblock only.
 */

export interface BaseEventPayload {
  timestamp?: string;
  correlationId?: string;
}

export interface UserSignedUpPayload extends BaseEventPayload {
  userId: string;
  email: string;
  orgId: string;
  role?: string;
}

export interface UserSignedInPayload extends BaseEventPayload {
  userId: string;
  email: string;
  orgId: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface UserSignedOutPayload extends BaseEventPayload {
  userId: string;
  orgId?: string;
}

export interface UserBlockedPayload extends BaseEventPayload {
  userId: string;
  orgId: string;
  blockedBy?: string;
  reason?: string;
}

export interface UserUnblockedPayload extends BaseEventPayload {
  userId: string;
  orgId: string;
  unblockedBy?: string;
}

export interface UserDeletedPayload extends BaseEventPayload {
  userId: string;
  orgId: string;
  deletedBy?: string;
}

export interface UserPiiShreddedPayload extends BaseEventPayload {
  userId: string;
  shreddedAt: string;
}

export interface OrganizationCreatedPayload extends BaseEventPayload {
  orgId: string;
  orgName: string;
  slug: string;
  creatorUserId?: string;
}

export interface OrganizationUpdatedPayload extends BaseEventPayload {
  orgId: string;
  orgName: string;
  slug: string;
}

export interface OrganizationSwitchedPayload extends BaseEventPayload {
  userId: string;
  targetOrgId: string;
  previousOrgId?: string;
}

export interface OrganizationDeletedPayload extends BaseEventPayload {
  orgId: string;
  deletedBy?: string;
}

export interface ApiKeyCreatedPayload extends BaseEventPayload {
  keyId: string;
  orgId: string;
  userId?: string;
  keyType: string;
  name: string;
  permissions: string[];
  expiresAtMs?: number;
}

export interface ApiKeyRevokedPayload extends BaseEventPayload {
  keyId: string;
  orgId?: string;
  revokedBy?: string;
}

export interface RelationTupleCreatedPayload extends BaseEventPayload {
  namespace: string;
  objectId: string;
  relation: string;
  subjectId: string;
  orgId: string;
}

export interface RelationTupleRevokedPayload extends BaseEventPayload {
  namespace: string;
  objectId: string;
  relation: string;
  subjectId: string;
  orgId: string;
}

export interface HoneytokenTrippedPayload extends BaseEventPayload {
  tokenId: string;
  tokenPrefix: string;
  ipAddress: string;
  userAgent: string;
  actionTaken: string;
}

export interface BreakGlassActivatedPayload extends BaseEventPayload {
  sessionId: string;
  operatorUserId: string;
  targetOrgId: string;
  ticketId: string;
  reason: string;
  expiresAt: string;
}

export interface BreakGlassTerminatedPayload extends BaseEventPayload {
  sessionId: string;
  operatorUserId: string;
  targetOrgId: string;
  terminatedBy: string;
}

export interface WormAuditSealedPayload extends BaseEventPayload {
  archiveId: string;
  merkleRoot: string;
  segmentStartMs: number;
  segmentEndMs: number;
  recordCount: number;
}

/**
 * @file organization.service.ts
 * @description Domain Service for Multi-Tenant Organization Lifecycle, Provisioning, and Context Switching.
 *
 * OVERALL ALGORITHM:
 * 1. Provision organization: Normalize inputs, generate deterministic slug if absent, and persist organization with duplicate catch handling.
 * 2. Organization mutation: Validate input schema, update repository, and return fresh record or throw ValidationError.
 * 3. Context switching: Validate user association with target organization using safe array lookup ->
 *    verify user existence -> revoke previous token in denylist -> issue new scoped token ->
 *    record organization switch audit log asynchronously without blocking response.
 */

import type { AuthRepositoryPort, OrganizationRecord } from '../repository';
import type { CreateOrganizationInput, UpdateOrganizationInput } from '../types';
import type { AuthTokenPayload } from '../../../shared/types/auth.types';
import { CreateOrganizationInputSchema, UpdateOrganizationInputSchema } from '../schema/auth.schema';
import {
  OrgAlreadyExistsError,
  InsufficientPermissionError,
  InvalidCredentialsError,
  ValidationError,
} from '../../../shared/errors/auth.errors';
import { verifyToken, createToken } from '../../../shared/utils/jwt.util';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { normalizeString } from '../../../shared/utils/string.util';
import { trace } from '@chief-strategist-j/shared-infra';

export class OrganizationDomainService {
  constructor(private readonly repo: AuthRepositoryPort) {}

  async listOrganizations(userId: string): Promise<OrganizationRecord[]> {
    const normalizedUserId = normalizeString(userId);
    return this.repo.listOrganizationsByUserId(normalizedUserId);
  }

  async getOrganization(orgId: string): Promise<OrganizationRecord> {
    const normalizedOrgId = normalizeString(orgId);
    const org = await this.repo.getOrganizationById(normalizedOrgId);
    if (!org) throw new ValidationError('Organization not found');
    return org;
  }

  async createOrganization(
    input: CreateOrganizationInput,
    creatorUserId?: string,
  ): Promise<{ id: string; name: string; slug: string }> {
    const validated = CreateOrganizationInputSchema.parse(input);
    const orgName = normalizeString(validated.name);
    const orgId = `org_${Math.random().toString(36).substring(2, 9)}`;
    const slug = validated.slug
      ? normalizeString(validated.slug, 'lower')
      : orgName.toLowerCase().replace(/[^a-z0-9]+/g, '-');

    try {
      await this.repo.createOrganization({ id: orgId, name: orgName, slug }, creatorUserId);
    } catch (err: unknown) {
      if (err instanceof Error && err.message.includes('Organization name already exists')) {
        throw new OrgAlreadyExistsError(orgName);
      }
      throw err;
    }

    return { id: orgId, name: orgName, slug };
  }

  async updateOrganization(orgId: string, input: UpdateOrganizationInput): Promise<OrganizationRecord> {
    const normalizedOrgId = normalizeString(orgId);
    const validated = UpdateOrganizationInputSchema.parse(input);
    await this.repo.updateOrganization(normalizedOrgId, validated);
    const updated = await this.repo.getOrganizationById(normalizedOrgId);
    if (!updated) throw new ValidationError('Organization not found');
    return updated;
  }

  async deleteOrganization(orgId: string): Promise<void> {
    const normalizedOrgId = normalizeString(orgId);
    await this.repo.deleteOrganization(normalizedOrgId);
  }

  async switchOrganization(
    userId: string,
    targetOrgId: string,
    currentToken: string,
  ): Promise<{ token: string; payload: AuthTokenPayload }> {
    const normalizedUserId = normalizeString(userId);
    const normalizedTargetOrgId = normalizeString(targetOrgId);
    const normalizedToken = normalizeString(currentToken);

    const orgs = await this.repo.listOrganizationsByUserId(normalizedUserId);
    const orgList = Array.isArray(orgs) ? orgs : [];
    const target = orgList.find((o) => o && o.id === normalizedTargetOrgId);
    if (!target) throw new InsufficientPermissionError('target organization');

    const user = await this.repo.findUserById(normalizedUserId);
    if (!user) throw new InvalidCredentialsError();

    const oldPayload = verifyToken(normalizedToken);
    if (typeof (this.repo as any).addTokenToDenylist === 'function') {
      await (this.repo as any).addTokenToDenylist(normalizedToken, oldPayload.exp * 1000);
    }

    const token = createToken(user.id, user.email, {
      org_id: target.id,
      org_name: target.name,
      role: user.role,
    });
    const newPayload = verifyToken(token);

    this.executeAsync(async () => {
      await this.repo.recordAuditLog({
        id: `audit_${Math.random().toString(36).substring(2, 9)}`,
        user_id: user.id,
        org_id: target.id,
        event_type: AUTH_CONSTANTS.AUDIT_EVENT_ORG_SWITCH,
        ip_address: '0.0.0.0',
        user_agent: 'server',
        timestamp_ms: Date.now(),
      });
    });

    return { token, payload: newPayload };
  }

  private executeAsync(fn: () => Promise<unknown>): void {
    Promise.resolve()
      .then(fn)
      .catch((err: unknown) => {
        const span = trace.getActiveSpan();
        if (span && err instanceof Error) {
          span.recordException(err);
        }
      });
  }
}

/**
 * @file honeytoken.service.ts
 * @description Domain orchestrator for Honeytokens & Active Canary Secret Scanning (ADR 0041).
 *
 * EXECUTION ALGORITHM:
 * 1. Generate high-entropy CSPRNG tokens with canonical prefix ht_canary_.
 * 2. Store salted SHA-256 digests in persistence layer (no plain secrets at rest).
 * 3. Inspect incoming candidate tokens during gateway authentication.
 * 4. On canary tripwire match:
 *    a. Update trip counter and forensic metadata in database.
 *    b. Push attacker IP to Redis denylist with emergency security TTL.
 *    c. Emit security alert to Kafka topic for SIEM / SOC ingestion.
 *    d. Return silent trip status to caller without leaking canary detection.
 */

import crypto from 'node:crypto';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { ValidationError } from '../../../shared/errors/auth.errors';
import { withSpan } from '../../../infra/tracing/tracer';
import type { AuthRepositoryPort } from '../repository';
import type { HoneytokenRecord } from '../../../shared/types/auth.types';

export interface CreateHoneytokenInput {
  org_id: string;
  name: string;
  deployed_location?: string;
}

export interface HoneytokenTripResult {
  isHoneytoken: boolean;
  tripped: boolean;
  honeytokenId?: string;
  name?: string;
  orgId?: string;
}

export class HoneytokenService {
  constructor(
    private readonly repo: AuthRepositoryPort,
    private readonly redisClient?: any,
    private readonly eventProducer?: any
  ) {}

  hashToken(rawToken: string): string {
    return crypto.createHash(AUTH_CONSTANTS.CRYPTO.ALGORITHM_SHA256).update(rawToken).digest(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX);
  }

  async createHoneytoken(input: CreateHoneytokenInput): Promise<{
    id: string;
    token: string;
    prefix: string;
    name: string;
    org_id: string;
    status: 'ACTIVE';
    created_at_ms: number;
  }> {
    return withSpan('HoneytokenService.createHoneytoken', async () => {
      if (!input.name || input.name.trim() === '') {
        throw new ValidationError('Honeytoken name is required');
      }
      if (!input.org_id || input.org_id.trim() === '') {
        throw new ValidationError('Organization ID is required');
      }

      const prefix = AUTH_CONSTANTS.HONEYTOKEN.DEFAULT_PREFIX;
      const entropy = crypto.randomBytes(24).toString('hex');
      const token = `${prefix}${entropy}`;
      const tokenHash = this.hashToken(token);
      const id = `ht_${crypto.randomBytes(12).toString('hex')}`;
      const nowMs = Date.now();

      const record: HoneytokenRecord = {
        id,
        token_hash: tokenHash,
        token_prefix: prefix,
        name: input.name.trim(),
        org_id: input.org_id,
        deployed_location: input.deployed_location?.trim() || null,
        tripwire_count: 0,
        last_tripped_at_ms: null,
        last_tripped_ip: null,
        last_tripped_user_agent: null,
        status: AUTH_CONSTANTS.HONEYTOKEN.STATUS_ACTIVE,
        created_at_ms: nowMs,
      };

      await this.repo.saveHoneytoken(record);

      return {
        id,
        token,
        prefix,
        name: record.name,
        org_id: record.org_id,
        status: 'ACTIVE',
        created_at_ms: nowMs,
      };
    });
  }

  async inspectAndTrip(
    rawToken: string,
    metadata: { ip: string; userAgent: string }
  ): Promise<HoneytokenTripResult> {
    return withSpan('HoneytokenService.inspectAndTrip', async (span) => {
      if (!rawToken || !rawToken.startsWith(AUTH_CONSTANTS.HONEYTOKEN.DEFAULT_PREFIX)) {
        return { isHoneytoken: false, tripped: false };
      }

      const tokenHash = this.hashToken(rawToken);
      const canary = await this.repo.findHoneytokenByHash(tokenHash);

      if (!canary) {
        return { isHoneytoken: false, tripped: false };
      }

      const nowMs = Date.now();
      span.setAttribute('security.honeytoken.tripped', true);
      span.setAttribute('security.honeytoken.id', canary.id);
      span.setAttribute('security.attacker.ip', metadata.ip);

      await this.repo.recordHoneytokenTrip(canary.id, {
        ip: metadata.ip,
        userAgent: metadata.userAgent,
        timestampMs: nowMs,
      });

      if (this.redisClient && metadata.ip) {
        const key = `${AUTH_CONSTANTS.HONEYTOKEN.CACHE_DENYLIST_PREFIX}${metadata.ip}`;
        try {
          await this.redisClient.set(
            key,
            JSON.stringify({ reason: 'HONEYTOKEN_TRIPWIRE', canaryId: canary.id, timestamp: nowMs }),
            'EX',
            AUTH_CONSTANTS.HONEYTOKEN.DEFAULT_BLOCK_TTL_SECONDS
          );
        } catch {
        }
      }

      if (this.eventProducer) {
        try {
          await this.eventProducer.emit(AUTH_CONSTANTS.HONEYTOKEN.KAFKA_TOPIC_TRIPPED, {
            canary_id: canary.id,
            canary_name: canary.name,
            org_id: canary.org_id,
            attacker_ip: metadata.ip,
            attacker_user_agent: metadata.userAgent,
            timestamp_ms: nowMs,
          });
        } catch {
        }
      }

      return {
        isHoneytoken: true,
        tripped: true,
        honeytokenId: canary.id,
        name: canary.name,
        orgId: canary.org_id,
      };
    });
  }

  async listHoneytokens(orgId: string): Promise<Array<HoneytokenRecord>> {
    return withSpan('HoneytokenService.listHoneytokens', async () => {
      if (!orgId) throw new ValidationError('Organization ID is required');
      return (await this.repo.listHoneytokensByOrgId(orgId)) as HoneytokenRecord[];
    });
  }

  async revokeHoneytoken(id: string, orgId: string): Promise<void> {
    return withSpan('HoneytokenService.revokeHoneytoken', async () => {
      if (!id || !orgId) throw new ValidationError('Honeytoken ID and Org ID are required');
      await this.repo.revokeHoneytoken(id, orgId);
    });
  }
}

import { createHash } from 'crypto';
import { AuthRepositoryPort } from '../repository';
import { WebhookSubscriptionRecord, WebhookDeliveryRecord } from '../../../shared/types/auth.types';
import { generateWebhookSecret } from '../../../shared/utils/webhook-signer.util';
import { withSpan, SpanKind } from '@chief-strategist-j/shared-infra';

export interface CreateWebhookSubscriptionInput {
  readonly orgId: string;
  readonly targetUrl: string;
  readonly subscribedEvents?: readonly string[];
}

export interface WebhookSubscriptionCreationResult {
  readonly subscription: WebhookSubscriptionRecord;
  readonly rawSigningSecret: string;
}

export interface DispatchWebhookEventInput {
  readonly orgId: string;
  readonly eventType: string;
  readonly payload: Record<string, unknown>;
}

export class WebhookService {
  private readonly repository: AuthRepositoryPort;

  constructor(repository: AuthRepositoryPort) {
    this.repository = repository;
  }

  async createSubscription(
    input: CreateWebhookSubscriptionInput
  ): Promise<WebhookSubscriptionCreationResult> {
    return withSpan('WebhookService.createSubscription', async (span) => {
      span?.setAttribute('auth.org_id', input.orgId);
      span?.setAttribute('auth.target_url', input.targetUrl);

      const rawSigningSecret = generateWebhookSecret();
      const secretHash = createHash('sha256').update(rawSigningSecret).digest('hex');
      const secretPrefix = rawSigningSecret.substring(0, 12);

      const now = Date.now();
      const randomSuffix = Math.random().toString(36).substring(2, 10);
      const id = `whsub_${now}_${randomSuffix}`;
      const publicId = `pub_whsub_${now}_${randomSuffix}`;

      const subscription: WebhookSubscriptionRecord = {
        id,
        public_id: publicId,
        org_id: input.orgId,
        target_url: input.targetUrl,
        secret_hash: secretHash,
        secret_prefix: secretPrefix,
        subscribed_events: input.subscribedEvents ? [...input.subscribedEvents] : ['*'],
        active: true,
        version: 1,
        created_at_ms: now,
        updated_at_ms: now,
      };

      await this.repository.saveWebhookSubscription(subscription);

      return {
        subscription,
        rawSigningSecret,
      };
    }, { kind: SpanKind.INTERNAL });
  }

  async listSubscriptions(orgId: string): Promise<WebhookSubscriptionRecord[]> {
    return withSpan('WebhookService.listSubscriptions', async (span) => {
      span?.setAttribute('auth.org_id', orgId);
      return this.repository.listWebhookSubscriptionsByOrgId(orgId);
    }, { kind: SpanKind.INTERNAL });
  }

  async getSubscription(id: string, orgId: string): Promise<WebhookSubscriptionRecord | null> {
    return withSpan('WebhookService.getSubscription', async (span) => {
      span?.setAttribute('auth.subscription_id', id);
      span?.setAttribute('auth.org_id', orgId);
      return this.repository.findWebhookSubscriptionById(id, orgId);
    }, { kind: SpanKind.INTERNAL });
  }

  async updateSubscription(
    id: string,
    orgId: string,
    patch: { target_url?: string; subscribed_events?: readonly string[]; active?: boolean }
  ): Promise<WebhookSubscriptionRecord | null> {
    return withSpan('WebhookService.updateSubscription', async (span) => {
      span?.setAttribute('auth.subscription_id', id);
      span?.setAttribute('auth.org_id', orgId);

      const existing = await this.repository.findWebhookSubscriptionById(id, orgId);
      if (!existing) return null;

      await this.repository.updateWebhookSubscription(id, orgId, patch);
      return this.repository.findWebhookSubscriptionById(id, orgId);
    }, { kind: SpanKind.INTERNAL });
  }

  async deleteSubscription(id: string, orgId: string): Promise<boolean> {
    return withSpan('WebhookService.deleteSubscription', async (span) => {
      span?.setAttribute('auth.subscription_id', id);
      span?.setAttribute('auth.org_id', orgId);

      const existing = await this.repository.findWebhookSubscriptionById(id, orgId);
      if (!existing) return false;

      await this.repository.deleteWebhookSubscription(id, orgId);
      return true;
    }, { kind: SpanKind.INTERNAL });
  }

  async recordDeliveryAttempt(
    deliveryInput: {
      subscriptionId: string;
      orgId: string;
      eventType: string;
      nonce: string;
      responseStatus: number;
      durationMs: number;
      success: boolean;
      failureReason?: string;
    }
  ): Promise<WebhookDeliveryRecord> {
    return withSpan('WebhookService.recordDeliveryAttempt', async () => {
      const now = Date.now();
      const randomSuffix = Math.random().toString(36).substring(2, 10);
      const deliveryRecord: WebhookDeliveryRecord = {
        id: `whdel_${now}_${randomSuffix}`,
        public_id: `pub_whdel_${now}_${randomSuffix}`,
        subscription_id: deliveryInput.subscriptionId,
        org_id: deliveryInput.orgId,
        event_type: deliveryInput.eventType,
        nonce: deliveryInput.nonce,
        response_status: deliveryInput.responseStatus,
        execution_duration_ms: deliveryInput.durationMs,
        success: deliveryInput.success,
        failure_reason: deliveryInput.failureReason ?? null,
        delivered_at_ms: now,
      };

      await this.repository.recordWebhookDelivery(deliveryRecord);
      return deliveryRecord;
    }, { kind: SpanKind.INTERNAL });
  }

  async listDeliveries(subscriptionId: string, orgId: string): Promise<WebhookDeliveryRecord[]> {
    return withSpan('WebhookService.listDeliveries', async (span) => {
      span?.setAttribute('auth.subscription_id', subscriptionId);
      span?.setAttribute('auth.org_id', orgId);
      return this.repository.listWebhookDeliveriesBySubscriptionId(subscriptionId, orgId);
    }, { kind: SpanKind.INTERNAL });
  }
}

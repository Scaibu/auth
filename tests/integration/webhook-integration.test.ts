import { describe, it, expect, beforeEach } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import {
  handleCreateWebhookSubscription,
  handleListWebhookSubscriptions,
  handleGetWebhookSubscription,
  handleUpdateWebhookSubscription,
  handleDeleteWebhookSubscription,
  handleListWebhookDeliveries,
} from '../../src/api/rest/v1/handlers/webhook.handler';

describe('Webhook Service Integration (ADR 0033)', () => {
  let adapter: AlloyDBOmniAuthAdapter;
  let service: AuthService;
  const orgId = 'org_enterprise_test';

  beforeEach(() => {
    adapter = new AlloyDBOmniAuthAdapter();
    service = new AuthService(adapter);
  });

  it('creates, lists, updates, and soft-deletes a webhook subscription', async () => {
    const session = {
      sub: 'usr_admin',
      org: { org_id: orgId, role: 'admin' },
      user: { id: 'usr_admin', email: 'admin@test.com', name: 'Admin', role: 'admin' },
    } as any;

    const createRes = await handleCreateWebhookSubscription(
      service,
      {
        target_url: 'https://consumer.example.com/webhooks/auth',
        subscribed_events: ['user.created', 'role.assigned'],
      },
      session
    ) as any;

    expect(createRes.subscription.target_url).toBe('https://consumer.example.com/webhooks/auth');
    expect(createRes.rawSigningSecret).toMatch(/^whsec_/);

    const subId = createRes.subscription.id;

    const listRes = await handleListWebhookSubscriptions(service, session) as any;
    expect(listRes.length).toBe(1);

    const getRes = await handleGetWebhookSubscription(service, subId, session) as any;
    expect(getRes.id).toBe(subId);

    const updateRes = await handleUpdateWebhookSubscription(
      service,
      subId,
      { active: false },
      session
    ) as any;
    expect(updateRes.active).toBe(false);

    const deleteRes = await handleDeleteWebhookSubscription(service, subId, session) as any;
    expect(deleteRes).toBe(true);

    const postDeleteList = await handleListWebhookSubscriptions(service, session) as any;
    expect(postDeleteList.length).toBe(0);
  });

  it('records and lists delivery attempts', async () => {
    const session = {
      sub: 'usr_admin',
      org: { org_id: orgId, role: 'admin' },
      user: { id: 'usr_admin', email: 'admin@test.com', name: 'Admin', role: 'admin' },
    } as any;

    const createRes = await handleCreateWebhookSubscription(
      service,
      { target_url: 'https://consumer.example.com/hook' },
      session
    ) as any;
    const subId = createRes.subscription.id;

    await (service as any).webhookService.recordDeliveryAttempt({
      subscriptionId: subId,
      orgId,
      eventType: 'role.assigned',
      nonce: 'nonce_test_123',
      responseStatus: 200,
      durationMs: 45,
      success: true,
    });

    const deliveriesRes = await handleListWebhookDeliveries(service, subId, session) as any;
    expect(deliveriesRes.length).toBe(1);
    expect(deliveriesRes[0].event_type).toBe('role.assigned');
    expect(deliveriesRes[0].response_status).toBe(200);
  });
});

import type { AuthService } from '../../../../features/auth/service';
import type { AuthTokenPayload } from '../../../../shared/types/auth.types';
import { UnauthorizedError, BadRequestError } from '../../../../shared/errors/auth.errors';

export async function handleCreateWebhookSubscription(
  service: AuthService,
  body: any,
  session?: AuthTokenPayload
): Promise<unknown> {
  const orgId = session?.org?.org_id;
  if (!orgId) {
    throw new UnauthorizedError('Authentication required');
  }
  if (!body?.target_url) {
    throw new BadRequestError('target_url is required');
  }

  return service.createWebhookSubscription({
    orgId,
    targetUrl: body.target_url,
    subscribedEvents: body.subscribed_events,
  });
}

export async function handleListWebhookSubscriptions(
  service: AuthService,
  session?: AuthTokenPayload
): Promise<unknown> {
  const orgId = session?.org?.org_id;
  if (!orgId) {
    throw new UnauthorizedError('Authentication required');
  }

  return service.listWebhookSubscriptions(orgId);
}

export async function handleGetWebhookSubscription(
  service: AuthService,
  id: string,
  session?: AuthTokenPayload
): Promise<unknown> {
  const orgId = session?.org?.org_id;
  if (!orgId) {
    throw new UnauthorizedError('Authentication required');
  }

  return service.getWebhookSubscription(id, orgId);
}

export async function handleUpdateWebhookSubscription(
  service: AuthService,
  id: string,
  body: any,
  session?: AuthTokenPayload
): Promise<unknown> {
  const orgId = session?.org?.org_id;
  if (!orgId) {
    throw new UnauthorizedError('Authentication required');
  }

  return service.updateWebhookSubscription(id, orgId, {
    target_url: body?.target_url,
    subscribed_events: body?.subscribed_events,
    active: body?.active,
  });
}

export async function handleDeleteWebhookSubscription(
  service: AuthService,
  id: string,
  session?: AuthTokenPayload
): Promise<unknown> {
  const orgId = session?.org?.org_id;
  if (!orgId) {
    throw new UnauthorizedError('Authentication required');
  }

  return service.deleteWebhookSubscription(id, orgId);
}

export async function handleListWebhookDeliveries(
  service: AuthService,
  subscriptionId: string,
  session?: AuthTokenPayload
): Promise<unknown> {
  const orgId = session?.org?.org_id;
  if (!orgId) {
    throw new UnauthorizedError('Authentication required');
  }

  return service.listWebhookDeliveries(subscriptionId, orgId);
}

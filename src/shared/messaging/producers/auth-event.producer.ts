/**
 * @file auth-event.producer.ts
 * @description Centralized Kafka producer for all domain, security, tenant, and compliance events.
 *
 * OVERALL ALGORITHM:
 * 1. Initialize centralized Kafka client with typed event producer.
 * 2. Connect to Kafka cluster on service initialization.
 * 3. Provide typed methods for publishing events across all domain boundaries.
 * 4. Automatically inject W3C trace context, correlation ID, and tenant ID headers via CentralMessagingTracer.
 * 5. Route security incidents to auth.security-events.v1 and audit records to auth.audit-events.v1.
 *
 * STRICT INVARIANT: ZERO inline comments inside function bodies. File header docblock only.
 */

import {
  createKafkaClient,
  CentralizedKafkaClient,
  KafkaHeaders,
  KafkaEvent,
  TypedEventProducer,
} from '@chief-strategist-j/shared-infra/messaging';
import { AUTH_KAFKA_TOPICS } from '../topics/auth-topics';
import {
  UserSignedUpPayload,
  UserSignedInPayload,
  UserSignedOutPayload,
  UserBlockedPayload,
  UserUnblockedPayload,
  UserDeletedPayload,
  UserPiiShreddedPayload,
  OrganizationCreatedPayload,
  OrganizationUpdatedPayload,
  OrganizationSwitchedPayload,
  OrganizationDeletedPayload,
  ApiKeyCreatedPayload,
  ApiKeyRevokedPayload,
  RelationTupleCreatedPayload,
  RelationTupleRevokedPayload,
  HoneytokenTrippedPayload,
  BreakGlassActivatedPayload,
  BreakGlassTerminatedPayload,
  WormAuditSealedPayload,
} from '../types/auth-event.types';

export class AuthEventProducer {
  private client: CentralizedKafkaClient;
  private producer: TypedEventProducer;

  constructor() {
    this.client = createKafkaClient('auth-service-producer');
    this.producer = new TypedEventProducer(this.client);
  }

  public async init(): Promise<void> {
    await this.client.connect();
  }

  public publishUserSignedUp(payload: UserSignedUpPayload, headers?: KafkaHeaders): Promise<KafkaEvent<UserSignedUpPayload>> {
    return this.producer.publish(AUTH_KAFKA_TOPICS.AUTH_EVENTS, 'USER_SIGNED_UP', payload, headers);
  }

  public publishUserSignedIn(payload: UserSignedInPayload, headers?: KafkaHeaders): Promise<KafkaEvent<UserSignedInPayload>> {
    return this.producer.publish(AUTH_KAFKA_TOPICS.AUTH_EVENTS, 'USER_SIGNED_IN', payload, headers);
  }

  public publishUserSignedOut(payload: UserSignedOutPayload, headers?: KafkaHeaders): Promise<KafkaEvent<UserSignedOutPayload>> {
    return this.producer.publish(AUTH_KAFKA_TOPICS.AUTH_EVENTS, 'USER_SIGNED_OUT', payload, headers);
  }

  public publishUserBlocked(payload: UserBlockedPayload, headers?: KafkaHeaders): Promise<KafkaEvent<UserBlockedPayload>> {
    return this.producer.publish(AUTH_KAFKA_TOPICS.SECURITY_EVENTS, 'USER_BLOCKED', payload, headers);
  }

  public publishUserUnblocked(payload: UserUnblockedPayload, headers?: KafkaHeaders): Promise<KafkaEvent<UserUnblockedPayload>> {
    return this.producer.publish(AUTH_KAFKA_TOPICS.SECURITY_EVENTS, 'USER_UNBLOCKED', payload, headers);
  }

  public publishUserDeleted(payload: UserDeletedPayload, headers?: KafkaHeaders): Promise<KafkaEvent<UserDeletedPayload>> {
    return this.producer.publish(AUTH_KAFKA_TOPICS.SECURITY_EVENTS, 'USER_DELETED', payload, headers);
  }

  public publishUserPiiShredded(payload: UserPiiShreddedPayload, headers?: KafkaHeaders): Promise<KafkaEvent<UserPiiShreddedPayload>> {
    return this.producer.publish(AUTH_KAFKA_TOPICS.SECURITY_EVENTS, 'USER_PII_SHREDDED', payload, headers);
  }

  public publishOrganizationCreated(payload: OrganizationCreatedPayload, headers?: KafkaHeaders): Promise<KafkaEvent<OrganizationCreatedPayload>> {
    return this.producer.publish(AUTH_KAFKA_TOPICS.AUTH_EVENTS, 'ORGANIZATION_CREATED', payload, headers);
  }

  public publishOrganizationUpdated(payload: OrganizationUpdatedPayload, headers?: KafkaHeaders): Promise<KafkaEvent<OrganizationUpdatedPayload>> {
    return this.producer.publish(AUTH_KAFKA_TOPICS.AUTH_EVENTS, 'ORGANIZATION_UPDATED', payload, headers);
  }

  public publishOrganizationSwitched(payload: OrganizationSwitchedPayload, headers?: KafkaHeaders): Promise<KafkaEvent<OrganizationSwitchedPayload>> {
    return this.producer.publish(AUTH_KAFKA_TOPICS.AUTH_EVENTS, 'ORGANIZATION_SWITCHED', payload, headers);
  }

  public publishOrganizationDeleted(payload: OrganizationDeletedPayload, headers?: KafkaHeaders): Promise<KafkaEvent<OrganizationDeletedPayload>> {
    return this.producer.publish(AUTH_KAFKA_TOPICS.SECURITY_EVENTS, 'ORGANIZATION_DELETED', payload, headers);
  }

  public publishApiKeyCreated(payload: ApiKeyCreatedPayload, headers?: KafkaHeaders): Promise<KafkaEvent<ApiKeyCreatedPayload>> {
    return this.producer.publish(AUTH_KAFKA_TOPICS.AUTH_EVENTS, 'API_KEY_CREATED', payload, headers);
  }

  public publishApiKeyRevoked(payload: ApiKeyRevokedPayload, headers?: KafkaHeaders): Promise<KafkaEvent<ApiKeyRevokedPayload>> {
    return this.producer.publish(AUTH_KAFKA_TOPICS.SECURITY_EVENTS, 'API_KEY_REVOKED', payload, headers);
  }

  public publishRelationTupleCreated(payload: RelationTupleCreatedPayload, headers?: KafkaHeaders): Promise<KafkaEvent<RelationTupleCreatedPayload>> {
    return this.producer.publish(AUTH_KAFKA_TOPICS.AUTH_EVENTS, 'RELATION_TUPLE_CREATED', payload, headers);
  }

  public publishRelationTupleRevoked(payload: RelationTupleRevokedPayload, headers?: KafkaHeaders): Promise<KafkaEvent<RelationTupleRevokedPayload>> {
    return this.producer.publish(AUTH_KAFKA_TOPICS.AUTH_EVENTS, 'RELATION_TUPLE_REVOKED', payload, headers);
  }

  public publishHoneytokenTripped(payload: HoneytokenTrippedPayload, headers?: KafkaHeaders): Promise<KafkaEvent<HoneytokenTrippedPayload>> {
    return this.producer.publish(AUTH_KAFKA_TOPICS.SECURITY_EVENTS, 'HONEYTOKEN_TRIPPED', payload, headers);
  }

  public publishBreakGlassActivated(payload: BreakGlassActivatedPayload, headers?: KafkaHeaders): Promise<KafkaEvent<BreakGlassActivatedPayload>> {
    return this.producer.publish(AUTH_KAFKA_TOPICS.SECURITY_EVENTS, 'BREAK_GLASS_ACTIVATED', payload, headers);
  }

  public publishBreakGlassTerminated(payload: BreakGlassTerminatedPayload, headers?: KafkaHeaders): Promise<KafkaEvent<BreakGlassTerminatedPayload>> {
    return this.producer.publish(AUTH_KAFKA_TOPICS.SECURITY_EVENTS, 'BREAK_GLASS_TERMINATED', payload, headers);
  }

  public publishWormAuditSealed(payload: WormAuditSealedPayload, headers?: KafkaHeaders): Promise<KafkaEvent<WormAuditSealedPayload>> {
    return this.producer.publish(AUTH_KAFKA_TOPICS.AUDIT_EVENTS, 'WORM_AUDIT_SEALED', payload, headers);
  }
}

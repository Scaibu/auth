/**
 * @file auth-topics.ts
 * @description Centralized Kafka topic declarations for domain, security, audit, and DLQ streams.
 *
 * OVERALL ALGORITHM:
 * 1. Declare domain-partitioned Kafka topics.
 * 2. Maintain strict versioning on all topic names.
 * 3. Provide separate topics for general operational events, security incidents, and compliance audits.
 * 4. Declare corresponding Dead Letter Queue (DLQ) topics for poisoned message handling.
 *
 * STRICT INVARIANT: ZERO inline comments inside functions. File header docblock only.
 */

export const AUTH_KAFKA_TOPICS = {
  AUTH_EVENTS: 'auth.events.v1',
  USER_EVENTS: 'auth.user-events.v1',
  SECURITY_EVENTS: 'auth.security-events.v1',
  AUDIT_EVENTS: 'auth.audit-events.v1',
  DLQ: {
    AUTH_EVENTS_DLQ: 'auth.events.v1-dlq',
    USER_EVENTS_DLQ: 'auth.user-events.v1-dlq',
    SECURITY_EVENTS_DLQ: 'auth.security-events.v1-dlq',
    AUDIT_EVENTS_DLQ: 'auth.audit-events.v1-dlq',
  },
} as const;

export type AuthKafkaTopic =
  | typeof AUTH_KAFKA_TOPICS.AUTH_EVENTS
  | typeof AUTH_KAFKA_TOPICS.USER_EVENTS
  | typeof AUTH_KAFKA_TOPICS.SECURITY_EVENTS
  | typeof AUTH_KAFKA_TOPICS.AUDIT_EVENTS
  | typeof AUTH_KAFKA_TOPICS.DLQ.AUTH_EVENTS_DLQ
  | typeof AUTH_KAFKA_TOPICS.DLQ.USER_EVENTS_DLQ
  | typeof AUTH_KAFKA_TOPICS.DLQ.SECURITY_EVENTS_DLQ
  | typeof AUTH_KAFKA_TOPICS.DLQ.AUDIT_EVENTS_DLQ;

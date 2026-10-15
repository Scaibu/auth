import { describe, it, expect } from 'vitest';
import { AUTH_CONFIG } from '../../src/config/env.config';

describe('Centralized Environment Configuration & Existence Validation', () => {
  it('should load all required connection properties from .env', () => {
    expect(AUTH_CONFIG.db.host).toBe('localhost');
    expect(AUTH_CONFIG.db.port).toBe(5432);
    expect(AUTH_CONFIG.db.user).toBe('admin');
    expect(AUTH_CONFIG.db.password).toBe('llmobs_s3cret_2026');
    expect(AUTH_CONFIG.db.name).toBe('llm_observability');
    expect(AUTH_CONFIG.db.url).toBe('postgresql://admin:llmobs_s3cret_2026@localhost:5432/llm_observability');

    expect(AUTH_CONFIG.redis.host).toBe('localhost');
    expect(AUTH_CONFIG.redis.port).toBe(6379);
    expect(AUTH_CONFIG.redis.password).toBe('llmobs_redis_s3cret_2026');
    expect(AUTH_CONFIG.redis.url).toBe('redis://:llmobs_redis_s3cret_2026@localhost:6379/0');

    expect(AUTH_CONFIG.kafka.brokers).toBe('localhost:9092');
    expect(AUTH_CONFIG.kafka.clientId).toBe('auth-client');
    expect(AUTH_CONFIG.kafka.securityProtocol).toBe('PLAINTEXT');

    expect(AUTH_CONFIG.otel.endpoint).toBe('https://localhost:4318');
    expect(AUTH_CONFIG.otel.grpcEndpoint).toBe('localhost:4317');
    expect(AUTH_CONFIG.otel.serviceName).toBe('auth-service');
    expect(AUTH_CONFIG.otel.insecure).toBe(true);

    expect(AUTH_CONFIG.serviceRegistry.url).toBe('http://localhost:31426');

    // Security Limits Configuration
    expect(AUTH_CONFIG.security.rateLimit.maxAttemptsPerIp).toBe(10);
    expect(AUTH_CONFIG.security.rateLimit.ipWindowMs).toBe(15 * 60 * 1000);
    expect(AUTH_CONFIG.security.rateLimit.maxFailedPerEmail).toBe(5);
    expect(AUTH_CONFIG.security.rateLimit.emailLockoutMs).toBe(15 * 60 * 1000);
    expect(AUTH_CONFIG.security.rateLimit.emailCaptchaThreshold).toBe(3);
    expect(AUTH_CONFIG.security.sessionDenylist.keyPrefix).toBe('auth:denylist:');
    expect(AUTH_CONFIG.security.sessionDenylist.defaultTtlSeconds).toBe(3600);

    // OIDC Configuration
    expect(AUTH_CONFIG.oidc.issuer).toBe('http://localhost:3001');
    expect(AUTH_CONFIG.oidc.codeTtlMs).toBe(300000);
    expect(AUTH_CONFIG.oidc.tokenTtlSeconds).toBe(3600);
  });
});


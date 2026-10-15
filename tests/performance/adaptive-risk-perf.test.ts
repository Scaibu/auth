import { describe, it, expect } from 'vitest';
import { AdaptiveRiskService } from '../../src/features/auth/services/adaptive-risk.service';

describe('Adaptive Risk Engine Performance Benchmarks', () => {
  const service = new AdaptiveRiskService('perf-test-secret');

  it('calculates Haversine distance and travel velocity in < 0.05ms per call under sustained load', () => {
    const iterations = 50000;
    const start = performance.now();

    for (let i = 0; i < iterations; i++) {
      service.calculateVelocityKmh(
        37.7749,
        -122.4194,
        1700000000000,
        51.5074,
        -0.1278,
        1700003600000,
      );
    }

    const elapsedMs = performance.now() - start;
    const avgLatencyMs = elapsedMs / iterations;

    expect(avgLatencyMs).toBeLessThan(0.05);
  });

  it('evaluates dynamic risk score and device fingerprinting in < 0.15ms per call', () => {
    const iterations = 20000;
    const telemetry = {
      ip: '198.51.100.5',
      latitude: 40.7128,
      longitude: -74.0060,
      asn: 'AS16509',
      isDatacenter: true,
    };
    const prevLogin = {
      id: 'lh_1',
      userId: 'usr_perf',
      ipAddress: '10.0.0.1',
      latitude: 37.7749,
      longitude: -122.4194,
      isDatacenter: false,
      deviceFingerprint: 'seed_fp',
      riskScore: 0,
      createdAtMs: Date.now() - 3600000,
    };

    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      service.evaluateRisk(telemetry, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', prevLogin);
    }
    const elapsedMs = performance.now() - start;
    const avgLatencyMs = elapsedMs / iterations;

    expect(avgLatencyMs).toBeLessThan(0.15);
  });
});

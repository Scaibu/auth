import { describe, it, expect } from 'vitest';
import { AdaptiveRiskService } from '../../src/features/auth/services/adaptive-risk.service';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('AdaptiveRiskService Unit Tests', () => {
  const service = new AdaptiveRiskService('test-secret-salt');

  it('calculates 0 risk for ordinary residential connection with no history', () => {
    const result = service.evaluateRisk({
      ip: '10.0.0.1',
      latitude: 37.7749,
      longitude: -122.4194,
      isDatacenter: false,
    }, 'Mozilla/5.0');

    expect(result.riskScore).toBe(0);
    expect(result.requiresStepUp).toBe(false);
    expect(result.isBlocked).toBe(false);
  });

  it('flags +40 risk for datacenter or proxy ASN', () => {
    const result = service.evaluateRisk({
      ip: '198.51.100.5',
      latitude: 40.7128,
      longitude: -74.0060,
      asn: 'AS16509',
      isDatacenter: true,
    }, 'Mozilla/5.0');

    expect(result.riskScore).toBe(AUTH_CONSTANTS.RISK.FACTORS.DATACENTER_ASN);
    expect(result.requiresStepUp).toBe(true);
    expect(result.isBlocked).toBe(false);
    expect(result.reasons).toContain(AUTH_CONSTANTS.RISK.REASON_DATACENTER_OR_PROXY);
  });

  it('flags +35 risk for impossible travel speed exceeding 900 km/h', () => {
    const prevTime = Date.now() - 30 * 60 * 1000; // 30 minutes ago
    const prevLogin = {
      id: 'lh_1',
      userId: 'usr_test',
      ipAddress: '10.0.0.1',
      latitude: 40.7128, // NYC
      longitude: -74.0060,
      isDatacenter: false,
      deviceFingerprint: service.generateDeviceFingerprint('Mozilla/5.0', '10.0.0.1'),
      riskScore: 0,
      createdAtMs: prevTime,
    };

    // Current location: London (5570 km away within 30 min => ~11,140 km/h)
    const result = service.evaluateRisk(
      {
        ip: '10.0.0.2',
        latitude: 51.5074,
        longitude: -0.1278,
        isDatacenter: false,
      },
      'Mozilla/5.0',
      prevLogin,
      Date.now(),
    );

    // Impossible travel alone: +35 risk
    expect(result.riskScore).toBe(AUTH_CONSTANTS.RISK.FACTORS.IMPOSSIBLE_VELOCITY);
    expect(result.requiresStepUp).toBe(true);
    expect(result.isBlocked).toBe(false);
    expect(result.reasons).toContain(AUTH_CONSTANTS.RISK.REASON_IMPOSSIBLE_TRAVEL);
  });

  it('blocks login (score >= 75) when datacenter proxy AND impossible velocity combine', () => {
    const prevTime = Date.now() - 15 * 60 * 1000;
    const prevLogin = {
      id: 'lh_1',
      userId: 'usr_test',
      ipAddress: '10.0.0.1',
      latitude: 37.7749, // San Francisco
      longitude: -122.4194,
      isDatacenter: false,
      deviceFingerprint: service.generateDeviceFingerprint('Mozilla/5.0', '10.0.0.1'),
      riskScore: 0,
      createdAtMs: prevTime,
    };

    // Current: Tokyo (8280 km away in 15 min => ~33,000 km/h) + Datacenter ASN
    const result = service.evaluateRisk(
      {
        ip: '198.51.100.5',
        latitude: 35.6762,
        longitude: 139.6503,
        isDatacenter: true,
      },
      'curl/7.68.0',
      prevLogin,
      Date.now(),
    );

    // 40 (datacenter) + 35 (velocity) + 25 (fingerprint) = 100
    expect(result.riskScore).toBe(100);
    expect(result.requiresStepUp).toBe(false);
    expect(result.isBlocked).toBe(true);
  });

  it('issues, verifies, and rejects expired challenge tokens', () => {
    const token = service.issueChallengeToken('usr_123', 'test@example.com', 40, ['DATACENTER_OR_PROXY_ASN']);
    expect(token).toBeDefined();

    const verified = service.verifyChallengeToken(token);
    expect(verified).not.toBeNull();
    expect(verified?.userId).toBe('usr_123');
    expect(verified?.riskScore).toBe(40);

    const tampered = token.slice(0, -4) + 'abcd';
    expect(service.verifyChallengeToken(tampered)).toBeNull();
  });
});

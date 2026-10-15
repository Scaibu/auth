import { createHmac, createHash } from 'node:crypto';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { withSpan } from '../../../infra/tracing/tracer';
import type { GeoLocationTelemetry, RiskEvaluationResult, LoginHistoryRecord } from '../types';

export class AdaptiveRiskService {
  private readonly secretKey: string;

  constructor(secretKey = 'test-risk-engine-secret-key-default') {
    this.secretKey = secretKey;
  }

  generateDeviceFingerprint(userAgent?: string): string {
    const raw = `${userAgent || 'unknown'}`;
    return createHash(AUTH_CONSTANTS.CRYPTO.ALGORITHM_SHA256).update(raw).digest(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX);
  }

  calculateHaversineDistanceKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
    const toRad = (deg: number): number => (deg * Math.PI) / 180;
    const dLat = toRad(lat2 - lat1);
    const dLon = toRad(lon2 - lon1);
    const phi1 = toRad(lat1);
    const phi2 = toRad(lat2);

    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.sin(dLon / 2) * Math.sin(dLon / 2) * Math.cos(phi1) * Math.cos(phi2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return AUTH_CONSTANTS.RISK.EARTH_RADIUS_KM * c;
  }

  calculateVelocityKmh(
    prevLat?: number,
    prevLon?: number,
    prevTimeMs?: number,
    currLat?: number,
    currLon?: number,
    currTimeMs?: number,
  ): number {
    if (
      prevLat === undefined ||
      prevLon === undefined ||
      prevTimeMs === undefined ||
      currLat === undefined ||
      currLon === undefined ||
      currTimeMs === undefined
    ) {
      return 0;
    }

    const timeDiffSeconds = (currTimeMs - prevTimeMs) / 1000;
    if (timeDiffSeconds < 10) {
      return 0;
    }

    const timeDiffHours = timeDiffSeconds / 3600;
    const distanceKm = this.calculateHaversineDistanceKm(prevLat, prevLon, currLat, currLon);
    return distanceKm / timeDiffHours;
  }

  evaluateRisk(
    currentTelemetry: GeoLocationTelemetry,
    userAgent?: string,
    previousLogin?: LoginHistoryRecord | null,
    nowMs = Date.now(),
  ): RiskEvaluationResult {
    let score = 0;
    const reasons: string[] = [];
    const currentFingerprint = this.generateDeviceFingerprint(userAgent);

    if (currentTelemetry.isDatacenter) {
      score += AUTH_CONSTANTS.RISK.FACTORS.DATACENTER_ASN;
      reasons.push(AUTH_CONSTANTS.RISK.REASON_DATACENTER_OR_PROXY);
    }

    let calculatedVelocity = 0;
    if (previousLogin && previousLogin.latitude !== undefined && previousLogin.longitude !== undefined) {
      calculatedVelocity = this.calculateVelocityKmh(
        previousLogin.latitude,
        previousLogin.longitude,
        previousLogin.createdAtMs,
        currentTelemetry.latitude,
        currentTelemetry.longitude,
        nowMs,
      );

      if (calculatedVelocity > AUTH_CONSTANTS.RISK.MAX_VELOCITY_KMH) {
        score += AUTH_CONSTANTS.RISK.FACTORS.IMPOSSIBLE_VELOCITY;
        reasons.push(AUTH_CONSTANTS.RISK.REASON_IMPOSSIBLE_TRAVEL);
      }
    }

    if (previousLogin && previousLogin.deviceFingerprint !== currentFingerprint) {
      score += AUTH_CONSTANTS.RISK.FACTORS.DEVICE_FINGERPRINT_SHIFT;
      reasons.push(AUTH_CONSTANTS.RISK.REASON_DEVICE_FINGERPRINT_SHIFT);
    }

    const finalScore = Math.min(100, score);
    const requiresStepUp =
      finalScore >= AUTH_CONSTANTS.RISK.THRESHOLDS.LOW && finalScore < AUTH_CONSTANTS.RISK.THRESHOLDS.HIGH;
    const isBlocked = finalScore >= AUTH_CONSTANTS.RISK.THRESHOLDS.HIGH;

    withSpan('auth.risk.evaluated', async (span) => {
      span.setAttribute('risk.score', finalScore);
      span.setAttribute('risk.is_blocked', isBlocked);
      span.setAttribute('risk.requires_step_up', requiresStepUp);
      span.setAttribute('risk.velocity_kmh', calculatedVelocity);
      span.setAttribute('risk.is_datacenter', Boolean(currentTelemetry.isDatacenter));
    }).catch(() => {});

    return {
      riskScore: finalScore,
      reasons: Object.freeze(reasons),
      requiresStepUp,
      isBlocked,
      currentTelemetry: {
        ...currentTelemetry,
        deviceFingerprint: currentFingerprint,
      },
    };
  }

  issueChallengeToken(userId: string, email: string, riskScore: number, reasons: readonly string[]): string {
    const expiresAt = Date.now() + AUTH_CONSTANTS.RISK.CHALLENGE_TTL_MS;
    const payload = JSON.stringify({
      type: AUTH_CONSTANTS.RISK.TOKEN_TYPE,
      userId,
      email,
      riskScore,
      reasons,
      exp: expiresAt,
    });
    const payloadB64 = Buffer.from(payload, 'utf8').toString('base64url');
    const signature = createHmac(AUTH_CONSTANTS.CRYPTO.ALGORITHM_SHA256, this.secretKey)
      .update(payloadB64)
      .digest(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX);
    return `${payloadB64}.${signature}`;
  }

  verifyChallengeToken(
    token: string,
  ): { userId: string; email: string; riskScore: number; reasons: readonly string[] } | null {
    const parts = token.split('.');
    if (parts.length !== 2) {
      return null;
    }
    const [payloadB64, signature] = parts;
    const expectedSig = createHmac(AUTH_CONSTANTS.CRYPTO.ALGORITHM_SHA256, this.secretKey)
      .update(payloadB64!)
      .digest(AUTH_CONSTANTS.CRYPTO.ENCODING_HEX);
    if (signature !== expectedSig) {
      return null;
    }

    try {
      const payloadStr = Buffer.from(payloadB64!, 'base64url').toString('utf8');
      const data = JSON.parse(payloadStr);
      if (data.type !== AUTH_CONSTANTS.RISK.TOKEN_TYPE || !data.userId || data.exp < Date.now()) {
        return null;
      }
      return {
        userId: data.userId,
        email: data.email,
        riskScore: data.riskScore,
        reasons: data.reasons || [],
      };
    } catch {
      return null;
    }
  }
}

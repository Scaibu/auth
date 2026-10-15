import { createHmac, timingSafeEqual, randomBytes } from 'crypto';

export interface WebhookSignatureResult {
  readonly signatureHeader: string;
  readonly nonce: string;
  readonly timestamp: number;
}

export function generateWebhookSecret(): string {
  return `whsec_${randomBytes(24).toString('hex')}`;
}

export function buildCanonicalWebhookString(
  timestamp: number,
  nonce: string,
  rawJsonBody: string
): string {
  return `t.${timestamp}.n.${nonce}.b.${rawJsonBody}`;
}

export function signWebhookPayload(
  rawJsonBody: string,
  secret: string,
  timestampMs?: number,
  nonceOverride?: string
): WebhookSignatureResult {
  const timestamp = timestampMs ?? Date.now();
  const nonce = nonceOverride ?? randomBytes(16).toString('hex');
  const canonical = buildCanonicalWebhookString(timestamp, nonce, rawJsonBody);

  const hmac = createHmac('sha256', secret).update(canonical).digest('hex');
  const signatureHeader = `t=${timestamp},v1=${hmac}`;

  return {
    signatureHeader,
    nonce,
    timestamp,
  };
}

export function verifyWebhookSignature(
  rawJsonBody: string,
  signatureHeader: string,
  nonceHeader: string,
  secret: string,
  maxDriftSeconds: number = 300
): { readonly isValid: boolean; readonly reason?: string } {
  if (!signatureHeader || !nonceHeader || !secret) {
    return { isValid: false, reason: 'E_MISSING_SIGNATURE_HEADERS' };
  }

  const parts = signatureHeader.split(',');
  let timestampStr: string | undefined;
  let incomingHmac: string | undefined;

  for (const part of parts) {
    const [key, val] = part.split('=');
    if (key === 't') timestampStr = val;
    if (key === 'v1') incomingHmac = val;
  }

  if (!timestampStr || !incomingHmac) {
    return { isValid: false, reason: 'E_INVALID_SIGNATURE_FORMAT' };
  }

  const timestamp = Number(timestampStr);
  if (isNaN(timestamp)) {
    return { isValid: false, reason: 'E_INVALID_TIMESTAMP' };
  }

  const now = Date.now();
  const driftMs = Math.abs(now - timestamp);
  if (driftMs > maxDriftSeconds * 1000) {
    return { isValid: false, reason: 'E_WEBHOOK_TIMESTAMP_EXPIRED' };
  }

  const canonical = buildCanonicalWebhookString(timestamp, nonceHeader, rawJsonBody);
  const expectedHmac = createHmac('sha256', secret).update(canonical).digest('hex');

  const incomingBuf = Buffer.from(incomingHmac, 'hex');
  const expectedBuf = Buffer.from(expectedHmac, 'hex');

  if (incomingBuf.length !== expectedBuf.length) {
    return { isValid: false, reason: 'E_SIGNATURE_LENGTH_MISMATCH' };
  }

  if (!timingSafeEqual(incomingBuf, expectedBuf)) {
    return { isValid: false, reason: 'E_SIGNATURE_MISMATCH' };
  }

  return { isValid: true };
}

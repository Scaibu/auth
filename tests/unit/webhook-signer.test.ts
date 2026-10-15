import { describe, it, expect } from 'vitest';
import {
  generateWebhookSecret,
  signWebhookPayload,
  verifyWebhookSignature,
  buildCanonicalWebhookString,
} from '../../src/shared/utils/webhook-signer.util';

describe('Webhook Cryptographic Signatures & Anti-Replay Defense (ADR 0033)', () => {
  const secret = 'whsec_9876543210abcdef9876543210abcdef';
  const testPayload = JSON.stringify({
    event: 'role.assigned',
    user_id: 'usr_enterprise99',
    role_id: 'crole_admin',
    timestamp: 1729000000000,
  });

  describe('Secret Generation', () => {
    it('generates a 256-bit cryptographically secure whsec_ prefixed secret', () => {
      const secret1 = generateWebhookSecret();
      const secret2 = generateWebhookSecret();

      expect(secret1).toMatch(/^whsec_[0-9a-f]{48}$/);
      expect(secret2).toMatch(/^whsec_[0-9a-f]{48}$/);
      expect(secret1).not.toBe(secret2);
    });
  });

  describe('Canonical String & Signing', () => {
    it('generates canonical signature string matching protocol format', () => {
      const canonical = buildCanonicalWebhookString(1729000000000, 'nonce_123', testPayload);
      expect(canonical).toBe(`t.1729000000000.n.nonce_123.b.${testPayload}`);
    });

    it('signs payload and outputs standardized headers', () => {
      const res = signWebhookPayload(testPayload, secret, 1729000000000, 'nonce_fixed');

      expect(res.nonce).toBe('nonce_fixed');
      expect(res.timestamp).toBe(1729000000000);
      expect(res.signatureHeader).toMatch(/^t=1729000000000,v1=[0-9a-f]{64}$/);
    });
  });

  describe('Signature Verification & Tamper Detection', () => {
    it('successfully verifies a valid signature within allowable drift window', () => {
      const now = Date.now();
      const signed = signWebhookPayload(testPayload, secret, now);

      const verification = verifyWebhookSignature(
        testPayload,
        signed.signatureHeader,
        signed.nonce,
        secret,
        300
      );

      expect(verification.isValid).toBe(true);
      expect(verification.reason).toBeUndefined();
    });

    it('rejects tampered JSON payload in flight', () => {
      const now = Date.now();
      const signed = signWebhookPayload(testPayload, secret, now);

      const tamperedPayload = JSON.stringify({
        event: 'role.assigned',
        user_id: 'usr_enterprise99',
        role_id: 'crole_SUPER_ADMIN_ESCALATED',
        timestamp: 1729000000000,
      });

      const verification = verifyWebhookSignature(
        tamperedPayload,
        signed.signatureHeader,
        signed.nonce,
        secret
      );

      expect(verification.isValid).toBe(false);
      expect(verification.reason).toBe('E_SIGNATURE_MISMATCH');
    });

    it('rejects expired webhook timestamps exceeding drift window', () => {
      const sixMinutesAgo = Date.now() - 360 * 1000;
      const signed = signWebhookPayload(testPayload, secret, sixMinutesAgo);

      const verification = verifyWebhookSignature(
        testPayload,
        signed.signatureHeader,
        signed.nonce,
        secret,
        300
      );

      expect(verification.isValid).toBe(false);
      expect(verification.reason).toBe('E_WEBHOOK_TIMESTAMP_EXPIRED');
    });

    it('rejects malformed signature headers missing v1 or timestamp', () => {
      const verification = verifyWebhookSignature(
        testPayload,
        'invalid_header_content',
        'nonce_123',
        secret
      );

      expect(verification.isValid).toBe(false);
      expect(verification.reason).toBe('E_INVALID_SIGNATURE_FORMAT');
    });

    it('rejects signature with incorrect signing secret', () => {
      const now = Date.now();
      const signed = signWebhookPayload(testPayload, secret, now);

      const verification = verifyWebhookSignature(
        testPayload,
        signed.signatureHeader,
        signed.nonce,
        'whsec_WRONG_SECRET_12345678901234567890'
      );

      expect(verification.isValid).toBe(false);
      expect(verification.reason).toBe('E_SIGNATURE_MISMATCH');
    });
  });
});

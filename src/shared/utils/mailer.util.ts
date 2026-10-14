/**
 * @file mailer.util.ts
 * @description Reusable utility functions for transactional email normalization, validation, and error parsing.
 *
 * OVERALL ALGORITHM:
 * 1. extractEmail: Strips display names to return normalized email addresses.
 * 2. validateEmailAddress: Verifies syntax compliance against RFC 5322 regex pattern.
 * 3. validateEmailMessage: Applies fail-fast guard validating presence and syntax of to, from, subject, and content bodies.
 * 4. formatMailerError: Serializes diverse runtime errors and HTTP status exceptions into standardized provider error strings.
 */

import type { EmailMessage } from '../ports/mailer.port';

const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

export interface MessageValidationResult {
  isValid: boolean;
  error?: string;
}

export function extractEmail(address: string): string {
  if (!address || typeof address !== 'string') return '';
  const match = address.match(/<(.+?)>/);
  return (match ? match[1]! : address).trim();
}

export function validateEmailAddress(address: string): boolean {
  const email = extractEmail(address);
  if (!email || email.length > 254) return false;
  return EMAIL_REGEX.test(email);
}

function isNonEmptyString(val: unknown): val is string {
  return typeof val === 'string' && val.trim().length > 0;
}

export function validateEmailMessage(message: EmailMessage | undefined | null): MessageValidationResult {
  if (message === null || message === undefined) {
    return { isValid: false, error: 'Email message object cannot be null or undefined' };
  }

  if (!isNonEmptyString(message.to)) {
    return { isValid: false, error: 'Missing or empty recipient (to) address' };
  }

  if (!validateEmailAddress(message.to)) {
    return { isValid: false, error: `Invalid recipient email address format: '${message.to}'` };
  }

  if (!isNonEmptyString(message.from)) {
    return { isValid: false, error: 'Missing or empty sender (from) address' };
  }

  if (!validateEmailAddress(message.from)) {
    return { isValid: false, error: `Invalid sender email address format: '${message.from}'` };
  }

  if (!isNonEmptyString(message.subject)) {
    return { isValid: false, error: 'Missing or empty email subject' };
  }

  const hasText = isNonEmptyString(message.textBody);
  const hasHtml = isNonEmptyString(message.htmlBody);

  if (!hasText && !hasHtml) {
    return { isValid: false, error: 'Email message must provide at least textBody or htmlBody content' };
  }

  if (isNonEmptyString(message.replyTo) && !validateEmailAddress(message.replyTo)) {
    return { isValid: false, error: `Invalid replyTo email address format: '${message.replyTo}'` };
  }

  return { isValid: true };
}

export function formatMailerError(provider: string, err: unknown): string {
  if (!err) {
    return `[${provider}] Unknown error occurred`;
  }

  if (err instanceof Error) {
    const status = (err as any).status || (err as any).statusCode;
    const data = (err as any).data;
    if (status) {
      const detail = typeof data === 'string' ? data : data ? JSON.stringify(data) : err.message;
      return `[${provider}] HTTP Error ${status}: ${detail}`;
    }
    return `[${provider}] ${err.message}`;
  }

  return `[${provider}] ${String(err)}`;
}

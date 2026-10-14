import { createHmac, randomBytes, createHash } from 'node:crypto';
import type { MfaPort } from '../../../shared/ports/mfa.port';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i]!;
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

function base32Decode(base32: string): Buffer {
  const sanitized = base32.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (let i = 0; i < sanitized.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(sanitized[i]!);
    if (idx === -1) {
      continue;
    }
    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

export class TotpMfaAdapter implements MfaPort {
  private readonly stepSeconds: number;
  private readonly digits: number;

  constructor(stepSeconds = 30, digits = 6) {
    this.stepSeconds = stepSeconds;
    this.digits = digits;
  }

  public generateSecret(lengthBytes = 20): string {
    const bytes = randomBytes(lengthBytes);
    return base32Encode(bytes);
  }

  public generateTotpUri(email: string, secret: string, issuer = 'ObservabilityAuth'): string {
    const encodedIssuer = encodeURIComponent(issuer);
    const encodedAccount = encodeURIComponent(email);
    return `otpauth://totp/${encodedIssuer}:${encodedAccount}?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=${this.digits}&period=${this.stepSeconds}`;
  }

  public generateCodeForCounter(secret: string, counter: number): string {
    const key = base32Decode(secret);
    const counterBuffer = Buffer.alloc(8);
    counterBuffer.writeBigInt64BE(BigInt(counter), 0);

    const hmac = createHmac('sha1', key);
    hmac.update(counterBuffer);
    const digest = hmac.digest();

    const offset = digest[digest.length - 1]! & 0x0f;
    const binary =
      ((digest[offset]! & 0x7f) << 24) |
      ((digest[offset + 1]! & 0xff) << 16) |
      ((digest[offset + 2]! & 0xff) << 8) |
      (digest[offset + 3]! & 0xff);

    const otp = binary % Math.pow(10, this.digits);
    return otp.toString().padStart(this.digits, '0');
  }

  public verifyTotpCode(secret: string, token: string, window = 1): boolean {
    if (!token || token.trim().length !== this.digits) {
      return false;
    }

    const trimmedToken = token.trim();
    const currentCounter = Math.floor(Date.now() / 1000 / this.stepSeconds);

    for (let offset = -window; offset <= window; offset++) {
      const candidateCounter = currentCounter + offset;
      const expectedCode = this.generateCodeForCounter(secret, candidateCounter);
      if (expectedCode === trimmedToken) {
        return true;
      }
    }

    return false;
  }

  public generateRecoveryCodes(count = 10): string[] {
    const codes: string[] = [];
    for (let i = 0; i < count; i++) {
      const raw = randomBytes(5).toString('hex');
      codes.push(`${raw.slice(0, 5)}-${raw.slice(5, 10)}`.toUpperCase());
    }
    return codes;
  }

  public hashRecoveryCode(code: string): string {
    const normalized = code.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
    return createHash('sha256').update(normalized).digest('hex');
  }
}

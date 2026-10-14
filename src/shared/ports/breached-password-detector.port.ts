/**
 * @file breached-password-detector.port.ts
 * @description Hexagonal Port contract for checking candidate passwords against breached credential dictionaries.
 *
 * OVERALL ALGORITHM:
 * 1. Define BreachedPasswordDetectorPort interface for NIST SP 800-63B password screening.
 * 2. checkIsPasswordPwned receives candidate password and returns boolean indicating if found in breach corpora.
 * 3. Adapters implement k-anonymity (e.g. HIBP) or offline local blooms without leaking plaintext passwords.
 */

export interface BreachedPasswordDetectorPort {
  checkIsPasswordPwned(password: string): Promise<boolean>;
}

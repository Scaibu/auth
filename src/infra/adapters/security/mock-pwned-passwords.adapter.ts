/**
 * @file mock-pwned-passwords.adapter.ts
 * @description Fast in-memory mock adapter for BreachedPasswordDetectorPort unit/integration tests.
 *
 * OVERALL ALGORITHM:
 * 1. Maintain a deterministic Set of known breached passwords (e.g. 'Password123!', 'PwnedPassword123!').
 * 2. Return true if password matches denylist, false otherwise.
 */

import type { BreachedPasswordDetectorPort } from '../../../shared/ports/breached-password-detector.port';

export class MockBreachedPasswordAdapter implements BreachedPasswordDetectorPort {
  private readonly breachedSet: Set<string>;

  constructor(initialBreached: string[] = ['Password123!', 'PwnedPassword123!', 'admin123456!', 'P@ssword123!']) {
    this.breachedSet = new Set(initialBreached);
  }

  async checkIsPasswordPwned(password: string): Promise<boolean> {
    return this.breachedSet.has(password);
  }

  addBreachedPassword(password: string): void {
    this.breachedSet.add(password);
  }

  clear(): void {
    this.breachedSet.clear();
  }
}

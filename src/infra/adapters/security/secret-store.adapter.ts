/**
 * @file secret-store.adapter.ts
 * @description Infrastructure adapter for resolving environment-based secrets.
 *
 * OVERALL ALGORITHM:
 * 1. Implement SecretStorePort to fetch secret values from runtime process environment.
 * 2. Return null if secret key is absent or undefined.
 *
 * STRICT INVARIANT: ZERO inline comments inside function bodies. File header docblock only.
 */

import type { SecretStorePort } from '../../../shared/ports/secret-store.port';

export class EnvSecretStoreAdapter implements SecretStorePort {
  async getSecret(key: string): Promise<string | null> {
    return process.env[key] ?? null;
  }
}

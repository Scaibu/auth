/**
 * @file secret-store.port.ts
 * @description Outbound port interface for retrieving application and infrastructure secrets.
 *
 * STRICT INVARIANT: ZERO inline comments inside function/type bodies. File header docblock only.
 */

export interface SecretStorePort {
  getSecret(key: string): Promise<string | null>;
}

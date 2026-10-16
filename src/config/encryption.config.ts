import { createHash } from 'crypto';

export interface EncryptionConfig {
  readonly masterKey: string;
  readonly masterKeyId: string;
  readonly blindIndexKey: string;
}

export const DEFAULT_ENCRYPTION_CONFIG: EncryptionConfig = Object.freeze({
  masterKey: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  masterKeyId: 'kek_v1_root',
  blindIndexKey: 'blind_index_secret_key_minimum_32_chars_long_entropy_seed',
});

export function loadEncryptionConfig(): EncryptionConfig {
  const masterKey = process.env.AUTH_MASTER_ENCRYPTION_KEY || DEFAULT_ENCRYPTION_CONFIG.masterKey;
  const masterKeyId = process.env.AUTH_MASTER_KEY_ID || DEFAULT_ENCRYPTION_CONFIG.masterKeyId;
  const blindIndexKey = process.env.AUTH_BLIND_INDEX_KEY || DEFAULT_ENCRYPTION_CONFIG.blindIndexKey;

  const keyBuffer = Buffer.from(masterKey, 'hex');
  const validKey = keyBuffer.length === 32
    ? masterKey
    : createHash('sha256').update(masterKey).digest('hex');

  return Object.freeze({
    masterKey: validKey,
    masterKeyId,
    blindIndexKey,
  });
}

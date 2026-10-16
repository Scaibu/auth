import { createHash } from 'crypto';

export interface EncryptionConfig {
  readonly masterKey: string;
  readonly masterKeyId: string;
  readonly blindIndexKey: string;
}

export function loadEncryptionConfig(): EncryptionConfig {
  const masterKey = process.env.AUTH_MASTER_ENCRYPTION_KEY;
  if (!masterKey || masterKey.trim() === '') {
    throw new Error('Missing required environment variable: AUTH_MASTER_ENCRYPTION_KEY does not exist');
  }

  const masterKeyId = process.env.AUTH_MASTER_KEY_ID || 'kek_v1_root';
  const blindIndexKey = process.env.AUTH_BLIND_INDEX_KEY;
  if (!blindIndexKey || blindIndexKey.trim() === '') {
    throw new Error('Missing required environment variable: AUTH_BLIND_INDEX_KEY does not exist');
  }

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

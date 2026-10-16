import { createCipheriv, createDecipheriv, randomBytes, createHmac } from 'crypto';
import { SecurityError } from '../errors/auth.errors';

export interface EnvelopeEncryptionContext {
  readonly orgId?: string;
  readonly fieldName?: string;
}

export interface KmsMasterKey {
  readonly kid: string;
  readonly key: Buffer;
}

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const DEK_LENGTH = 32;
const ENVELOPE_PREFIX = 'enc:v1:';

export function canonicalizeEmail(rawEmail: string): string {
  return rawEmail.trim().toLowerCase();
}

export function computeBlindIndex(value: string, secretKey: string): string {
  const normalized = canonicalizeEmail(value);
  return createHmac('sha256', secretKey).update(normalized).digest('hex');
}

export function generateUserDek(): Buffer {
  return randomBytes(DEK_LENGTH);
}

export function encryptEnvelope(
  plaintext: string,
  masterKey: Readonly<KmsMasterKey>,
  context?: Readonly<EnvelopeEncryptionContext>
): string {
  const dek = generateUserDek();
  const dataIv = randomBytes(IV_LENGTH);

  const dataCipher = createCipheriv(ALGORITHM, dek, dataIv);
  if (context) {
    const aad = `${context.orgId || ''}:${context.fieldName || ''}`;
    dataCipher.setAAD(Buffer.from(aad, 'utf-8'));
  }

  const encryptedData = Buffer.concat([
    dataCipher.update(plaintext, 'utf-8'),
    dataCipher.final(),
  ]);
  const dataAuthTag = dataCipher.getAuthTag();

  const dekIv = randomBytes(IV_LENGTH);
  const dekCipher = createCipheriv(ALGORITHM, masterKey.key, dekIv);
  dekCipher.setAAD(Buffer.from(masterKey.kid, 'utf-8'));

  const encryptedDek = Buffer.concat([
    dekCipher.update(dek),
    dekCipher.final(),
  ]);
  const dekAuthTag = dekCipher.getAuthTag();

  const payload = JSON.stringify({
    kid: masterKey.kid,
    dek_iv: dekIv.toString('base64url'),
    dek_tag: dekAuthTag.toString('base64url'),
    edek: encryptedDek.toString('base64url'),
    data_iv: dataIv.toString('base64url'),
    data_tag: dataAuthTag.toString('base64url'),
    ct: encryptedData.toString('base64url'),
  });

  return `${ENVELOPE_PREFIX}${Buffer.from(payload, 'utf-8').toString('base64url')}`;
}

export function encryptUserDek(dek: Buffer, masterKey: Readonly<KmsMasterKey>): string {
  const dekIv = randomBytes(IV_LENGTH);
  const dekCipher = createCipheriv(ALGORITHM, masterKey.key, dekIv);
  dekCipher.setAAD(Buffer.from(masterKey.kid, 'utf-8'));
  const encryptedDek = Buffer.concat([
    dekCipher.update(dek),
    dekCipher.final(),
  ]);
  const dekAuthTag = dekCipher.getAuthTag();

  const payload = JSON.stringify({
    kid: masterKey.kid,
    dek_iv: dekIv.toString('base64url'),
    dek_tag: dekAuthTag.toString('base64url'),
    edek: encryptedDek.toString('base64url'),
  });

  return `${ENVELOPE_PREFIX}${Buffer.from(payload, 'utf-8').toString('base64url')}`;
}

export function decryptUserDek(
  envelope: string,
  masterKeys: ReadonlyMap<string, Buffer> | Readonly<KmsMasterKey>
): Buffer {
  if (!envelope.startsWith(ENVELOPE_PREFIX)) {
    throw new SecurityError('Malformed user DEK envelope prefix');
  }

  const encoded = envelope.substring(ENVELOPE_PREFIX.length);
  let parsed: { readonly kid: string; readonly dek_iv: string; readonly dek_tag: string; readonly edek: string };
  try {
    const jsonStr = Buffer.from(encoded, 'base64url').toString('utf-8');
    parsed = JSON.parse(jsonStr);
  } catch {
    throw new SecurityError('Malformed user DEK payload');
  }

  let masterKeyBuffer: Buffer | undefined;
  if ('key' in masterKeys && masterKeys.kid === parsed.kid) {
    masterKeyBuffer = masterKeys.key;
  } else if (masterKeys instanceof Map) {
    masterKeyBuffer = masterKeys.get(parsed.kid);
  }

  if (!masterKeyBuffer) {
    throw new SecurityError(`Master key ${parsed.kid} not available for DEK decryption`);
  }

  try {
    const decipher = createDecipheriv(ALGORITHM, masterKeyBuffer, Buffer.from(parsed.dek_iv, 'base64url'));
    decipher.setAAD(Buffer.from(parsed.kid, 'utf-8'));
    decipher.setAuthTag(Buffer.from(parsed.dek_tag, 'base64url'));
    return Buffer.concat([decipher.update(Buffer.from(parsed.edek, 'base64url')), decipher.final()]);
  } catch {
    throw new SecurityError('User DEK authentication tag verification failed (key shredded or corrupted)');
  }
}

export function encryptWithDek(
  plaintext: string,
  dek: Buffer,
  context?: Readonly<EnvelopeEncryptionContext>
): string {
  const dataIv = randomBytes(IV_LENGTH);
  const dataCipher = createCipheriv(ALGORITHM, dek, dataIv);
  if (context) {
    const aad = `${context.orgId || ''}:${context.fieldName || ''}`;
    dataCipher.setAAD(Buffer.from(aad, 'utf-8'));
  }

  const encryptedData = Buffer.concat([
    dataCipher.update(plaintext, 'utf-8'),
    dataCipher.final(),
  ]);
  const dataAuthTag = dataCipher.getAuthTag();

  const payload = JSON.stringify({
    data_iv: dataIv.toString('base64url'),
    data_tag: dataAuthTag.toString('base64url'),
    ct: encryptedData.toString('base64url'),
  });

  return `${ENVELOPE_PREFIX}${Buffer.from(payload, 'utf-8').toString('base64url')}`;
}

export function decryptWithDek(
  envelope: string,
  dek: Buffer,
  context?: Readonly<EnvelopeEncryptionContext>
): string {
  if (!envelope.startsWith(ENVELOPE_PREFIX)) {
    return envelope;
  }

  const encoded = envelope.substring(ENVELOPE_PREFIX.length);
  let parsed: { readonly data_iv: string; readonly data_tag: string; readonly ct: string };
  try {
    parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf-8'));
  } catch {
    throw new SecurityError('Malformed envelope encryption payload');
  }

  try {
    const dataDecipher = createDecipheriv(ALGORITHM, dek, Buffer.from(parsed.data_iv, 'base64url'));
    if (context) {
      const aad = `${context.orgId || ''}:${context.fieldName || ''}`;
      dataDecipher.setAAD(Buffer.from(aad, 'utf-8'));
    }
    dataDecipher.setAuthTag(Buffer.from(parsed.data_tag, 'base64url'));

    const decrypted = Buffer.concat([
      dataDecipher.update(Buffer.from(parsed.ct, 'base64url')),
      dataDecipher.final(),
    ]);

    return decrypted.toString('utf-8');
  } catch {
    throw new SecurityError('Field ciphertext authentication tag verification failed');
  }
}

export function decryptEnvelope(
  envelope: string,
  masterKeys: ReadonlyMap<string, Buffer> | Readonly<KmsMasterKey>,
  context?: Readonly<EnvelopeEncryptionContext>
): string {
  if (!envelope.startsWith(ENVELOPE_PREFIX)) {
    return envelope;
  }

  const encoded = envelope.substring(ENVELOPE_PREFIX.length);
  let parsed: {
    readonly kid: string;
    readonly dek_iv: string;
    readonly dek_tag: string;
    readonly edek: string;
    readonly data_iv: string;
    readonly data_tag: string;
    readonly ct: string;
  };

  try {
    const jsonStr = Buffer.from(encoded, 'base64url').toString('utf-8');
    parsed = JSON.parse(jsonStr);
  } catch {
    throw new SecurityError('Malformed envelope encryption payload');
  }

  let masterKeyBuffer: Buffer | undefined;
  if ('key' in masterKeys && masterKeys.kid === parsed.kid) {
    masterKeyBuffer = masterKeys.key;
  } else if (masterKeys instanceof Map) {
    masterKeyBuffer = masterKeys.get(parsed.kid);
  }

  if (!masterKeyBuffer) {
    throw new SecurityError(`Master key ${parsed.kid} not available for envelope decryption`);
  }

  let dek: Buffer;
  try {
    const dekDecipher = createDecipheriv(
      ALGORITHM,
      masterKeyBuffer,
      Buffer.from(parsed.dek_iv, 'base64url')
    );
    dekDecipher.setAAD(Buffer.from(parsed.kid, 'utf-8'));
    dekDecipher.setAuthTag(Buffer.from(parsed.dek_tag, 'base64url'));

    dek = Buffer.concat([
      dekDecipher.update(Buffer.from(parsed.edek, 'base64url')),
      dekDecipher.final(),
    ]);
  } catch {
    throw new SecurityError('DEK integrity authentication verification failed');
  }

  try {
    const dataDecipher = createDecipheriv(
      ALGORITHM,
      dek,
      Buffer.from(parsed.data_iv, 'base64url')
    );
    if (context) {
      const aad = `${context.orgId || ''}:${context.fieldName || ''}`;
      dataDecipher.setAAD(Buffer.from(aad, 'utf-8'));
    }
    dataDecipher.setAuthTag(Buffer.from(parsed.data_tag, 'base64url'));

    const decrypted = Buffer.concat([
      dataDecipher.update(Buffer.from(parsed.ct, 'base64url')),
      dataDecipher.final(),
    ]);

    return decrypted.toString('utf-8');
  } catch {
    throw new SecurityError('Field ciphertext authentication tag verification failed');
  }
}

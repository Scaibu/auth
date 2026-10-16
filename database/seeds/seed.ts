import pg from 'pg';
import crypto from 'node:crypto';
import { AUTH_CONFIG } from '../../src/config/env.config';
import { hashPassword, hashApiKey } from '../../src/shared/utils/argon2.util';
import { computeBlindIndex, encryptEnvelope } from '../../src/shared/utils/envelope-encryption.util';

export interface SeedOptions {
  connectionString?: string;
  silent?: boolean;
}

export interface SeedResult {
  organizationId: string;
  adminUserId: string;
  viewerUserId: string;
  oauthClientId: string;
  apiKeyId: string;
}

export const SEED_CONSTANTS = {
  ORGANIZATION: {
    ID: 'org_enterprise_root_default',
    NAME: 'Default Enterprise',
    SLUG: 'default-enterprise',
  },
  ADMIN_USER: {
    ID: 'usr_admin_default_root',
    EMAIL: 'admin@observability.internal',
    PASSWORD: 'AdminPassword123!',
    NAME: 'System Administrator',
    ROLE: 'owner',
    USER_PERMISSIONS: ['*'],
  },
  VIEWER_USER: {
    ID: 'usr_viewer_default_root',
    EMAIL: 'viewer@observability.internal',
    PASSWORD: 'ViewerPassword123!',
    NAME: 'Standard Viewer',
    ROLE: 'viewer',
    USER_PERMISSIONS: ['read:*'],
  },
  OAUTH_CLIENT: {
    ID: 'client_internal_monitoring_root',
    NAME: 'Internal Monitoring Service',
    CLIENT_SECRET: 'm2m_super_secret_monitoring_key_2026',
    REDIRECT_URIS: ['https://monitoring.observability.internal/callback'],
    GRANT_TYPES: ['client_credentials', 'authorization_code'],
    RESPONSE_TYPES: ['code'],
    CLIENT_TYPE: 'confidential',
  },
  API_KEY: {
    ID: 'key_live_seed_test_root',
    RAW_KEY: 'live_seed_test_key_00000000000000000000000000000000',
    NAME: 'Live Seed Testing API Key',
    TYPE: 'admin',
    PERMISSIONS: ['read:*', 'write:*', 'admin:*'],
    IP_ALLOWLIST: ['127.0.0.1/32', '10.0.0.0/8'],
    RATE_QUOTA_RPM: 1000,
  },
} as const;

export async function runDatabaseSeed(options: SeedOptions = {}): Promise<SeedResult> {
  const connectionString = options.connectionString || AUTH_CONFIG.db.url;
  const log = options.silent ? () => {} : console.log;

  const pool = new pg.Pool({ connectionString });
  pool.on('error', (err: any) => {
    if (!options.silent) {
      console.warn('[db-seed] Pool error caught:', err?.message || err);
    }
  });

  const client = await pool.connect();
  const nowMs = Date.now();

  try {
    log('[db-seed] Starting database fixture seeding...');
    await client.query('BEGIN');

    // 1. Seed Root Organization
    log(`[db-seed] Seeding organization: ${SEED_CONSTANTS.ORGANIZATION.NAME}`);
    await client.query(
      `
      INSERT INTO auth_organizations (id, name, slug)
      VALUES ($1, $2, $3)
      ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        slug = EXCLUDED.slug,
        deleted_at = NULL
      `,
      [
        SEED_CONSTANTS.ORGANIZATION.ID,
        SEED_CONSTANTS.ORGANIZATION.NAME,
        SEED_CONSTANTS.ORGANIZATION.SLUG,
      ]
    );

    // 2. Prepare Hashes & Envelope Encryption Payloads
    const adminPasswordHash = await hashPassword(SEED_CONSTANTS.ADMIN_USER.PASSWORD);
    const viewerPasswordHash = await hashPassword(SEED_CONSTANTS.VIEWER_USER.PASSWORD);

    const masterKey = {
      kid: AUTH_CONFIG.encryption.masterKeyId,
      key: Buffer.from(AUTH_CONFIG.encryption.masterKey, 'hex'),
    };

    const adminBlindIndex = computeBlindIndex(
      SEED_CONSTANTS.ADMIN_USER.EMAIL,
      AUTH_CONFIG.encryption.blindIndexKey
    );
    const adminEmailEncrypted = encryptEnvelope(
      SEED_CONSTANTS.ADMIN_USER.EMAIL,
      masterKey,
      { orgId: SEED_CONSTANTS.ORGANIZATION.ID, fieldName: 'email' }
    );
    const adminNameEncrypted = encryptEnvelope(
      SEED_CONSTANTS.ADMIN_USER.NAME,
      masterKey,
      { orgId: SEED_CONSTANTS.ORGANIZATION.ID, fieldName: 'name' }
    );

    const viewerBlindIndex = computeBlindIndex(
      SEED_CONSTANTS.VIEWER_USER.EMAIL,
      AUTH_CONFIG.encryption.blindIndexKey
    );
    const viewerEmailEncrypted = encryptEnvelope(
      SEED_CONSTANTS.VIEWER_USER.EMAIL,
      masterKey,
      { orgId: SEED_CONSTANTS.ORGANIZATION.ID, fieldName: 'email' }
    );
    const viewerNameEncrypted = encryptEnvelope(
      SEED_CONSTANTS.VIEWER_USER.NAME,
      masterKey,
      { orgId: SEED_CONSTANTS.ORGANIZATION.ID, fieldName: 'name' }
    );

    // 3. Seed Super Admin User (Full envelope encryption + RLS bypass/setup)
    log(`[db-seed] Seeding admin user: ${SEED_CONSTANTS.ADMIN_USER.EMAIL}`);
    await client.query(
      `
      INSERT INTO auth_users (
        id, email, password_hash, name, org_id, org_name, role, email_verified,
        user_permissions, blocked, name_encrypted, email_encrypted, email_blind_index
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      ON CONFLICT (id) DO UPDATE SET
        email = EXCLUDED.email,
        password_hash = EXCLUDED.password_hash,
        name = EXCLUDED.name,
        org_id = EXCLUDED.org_id,
        org_name = EXCLUDED.org_name,
        role = EXCLUDED.role,
        email_verified = EXCLUDED.email_verified,
        user_permissions = EXCLUDED.user_permissions,
        blocked = EXCLUDED.blocked,
        name_encrypted = EXCLUDED.name_encrypted,
        email_encrypted = EXCLUDED.email_encrypted,
        email_blind_index = EXCLUDED.email_blind_index,
        deleted_at = NULL
      `,
      [
        SEED_CONSTANTS.ADMIN_USER.ID,
        SEED_CONSTANTS.ADMIN_USER.EMAIL,
        adminPasswordHash,
        SEED_CONSTANTS.ADMIN_USER.NAME,
        SEED_CONSTANTS.ORGANIZATION.ID,
        SEED_CONSTANTS.ORGANIZATION.NAME,
        SEED_CONSTANTS.ADMIN_USER.ROLE,
        true,
        SEED_CONSTANTS.ADMIN_USER.USER_PERMISSIONS,
        false,
        adminNameEncrypted,
        adminEmailEncrypted,
        adminBlindIndex,
      ]
    );

    // 4. Seed Viewer User
    log(`[db-seed] Seeding viewer user: ${SEED_CONSTANTS.VIEWER_USER.EMAIL}`);
    await client.query(
      `
      INSERT INTO auth_users (
        id, email, password_hash, name, org_id, org_name, role, email_verified,
        user_permissions, blocked, name_encrypted, email_encrypted, email_blind_index
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      ON CONFLICT (id) DO UPDATE SET
        email = EXCLUDED.email,
        password_hash = EXCLUDED.password_hash,
        name = EXCLUDED.name,
        org_id = EXCLUDED.org_id,
        org_name = EXCLUDED.org_name,
        role = EXCLUDED.role,
        email_verified = EXCLUDED.email_verified,
        user_permissions = EXCLUDED.user_permissions,
        blocked = EXCLUDED.blocked,
        name_encrypted = EXCLUDED.name_encrypted,
        email_encrypted = EXCLUDED.email_encrypted,
        email_blind_index = EXCLUDED.email_blind_index,
        deleted_at = NULL
      `,
      [
        SEED_CONSTANTS.VIEWER_USER.ID,
        SEED_CONSTANTS.VIEWER_USER.EMAIL,
        viewerPasswordHash,
        SEED_CONSTANTS.VIEWER_USER.NAME,
        SEED_CONSTANTS.ORGANIZATION.ID,
        SEED_CONSTANTS.ORGANIZATION.NAME,
        SEED_CONSTANTS.VIEWER_USER.ROLE,
        true,
        SEED_CONSTANTS.VIEWER_USER.USER_PERMISSIONS,
        false,
        viewerNameEncrypted,
        viewerEmailEncrypted,
        viewerBlindIndex,
      ]
    );

    // 5. Seed Multi-Tenant Membership (auth_user_organizations)
    await client.query(
      `
      INSERT INTO auth_user_organizations (user_id, org_id, role)
      VALUES 
        ($1, $2, $3),
        ($4, $5, $6)
      ON CONFLICT (user_id, org_id) DO UPDATE SET
        role = EXCLUDED.role
      `,
      [
        SEED_CONSTANTS.ADMIN_USER.ID,
        SEED_CONSTANTS.ORGANIZATION.ID,
        SEED_CONSTANTS.ADMIN_USER.ROLE,
        SEED_CONSTANTS.VIEWER_USER.ID,
        SEED_CONSTANTS.ORGANIZATION.ID,
        SEED_CONSTANTS.VIEWER_USER.ROLE,
      ]
    );

    // 6. Seed Confidential OAuth / OIDC Client
    const clientSecretHash = crypto
      .createHash('sha256')
      .update(SEED_CONSTANTS.OAUTH_CLIENT.CLIENT_SECRET)
      .digest('hex');

    log(`[db-seed] Seeding OAuth client: ${SEED_CONSTANTS.OAUTH_CLIENT.NAME}`);
    await client.query(
      `
      INSERT INTO auth_oauth_clients (
        id, org_id, client_name, client_secret_hash, redirect_uris,
        grant_types, response_types, client_type, status, created_at_ms
      )
      VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8, $9, $10)
      ON CONFLICT (id) DO UPDATE SET
        client_name = EXCLUDED.client_name,
        client_secret_hash = EXCLUDED.client_secret_hash,
        redirect_uris = EXCLUDED.redirect_uris,
        grant_types = EXCLUDED.grant_types,
        response_types = EXCLUDED.response_types,
        client_type = EXCLUDED.client_type,
        status = EXCLUDED.status,
        deleted_at = NULL
      `,
      [
        SEED_CONSTANTS.OAUTH_CLIENT.ID,
        SEED_CONSTANTS.ORGANIZATION.ID,
        SEED_CONSTANTS.OAUTH_CLIENT.NAME,
        clientSecretHash,
        JSON.stringify(SEED_CONSTANTS.OAUTH_CLIENT.REDIRECT_URIS),
        JSON.stringify(SEED_CONSTANTS.OAUTH_CLIENT.GRANT_TYPES),
        JSON.stringify(SEED_CONSTANTS.OAUTH_CLIENT.RESPONSE_TYPES),
        SEED_CONSTANTS.OAUTH_CLIENT.CLIENT_TYPE,
        'ACTIVE',
        nowMs,
      ]
    );

    // 7. Seed Pre-provisioned API Key (with CIDR allowlists & rate quotas)
    const keyHash = await hashApiKey(SEED_CONSTANTS.API_KEY.RAW_KEY);
    const keyPrefix = SEED_CONSTANTS.API_KEY.RAW_KEY.substring(0, 14);

    log(`[db-seed] Seeding API key: ${SEED_CONSTANTS.API_KEY.NAME}`);
    await client.query(
      `
      INSERT INTO auth_api_keys (
        key_id, org_id, key_type, key_hash, prefix, name, permissions, created_at_ms,
        revoked, ip_allowlist, rate_quota_rpm, total_requests_count, anomaly_flag
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      ON CONFLICT (key_id) DO UPDATE SET
        name = EXCLUDED.name,
        key_hash = EXCLUDED.key_hash,
        prefix = EXCLUDED.prefix,
        permissions = EXCLUDED.permissions,
        revoked = EXCLUDED.revoked,
        ip_allowlist = EXCLUDED.ip_allowlist,
        rate_quota_rpm = EXCLUDED.rate_quota_rpm,
        deleted_at = NULL
      `,
      [
        SEED_CONSTANTS.API_KEY.ID,
        SEED_CONSTANTS.ORGANIZATION.ID,
        SEED_CONSTANTS.API_KEY.TYPE,
        keyHash,
        keyPrefix,
        SEED_CONSTANTS.API_KEY.NAME,
        SEED_CONSTANTS.API_KEY.PERMISSIONS,
        nowMs,
        false,
        SEED_CONSTANTS.API_KEY.IP_ALLOWLIST,
        SEED_CONSTANTS.API_KEY.RATE_QUOTA_RPM,
        0,
        false,
      ]
    );

    await client.query('COMMIT');
    log('[db-seed] Database seeding completed successfully.');

    return {
      organizationId: SEED_CONSTANTS.ORGANIZATION.ID,
      adminUserId: SEED_CONSTANTS.ADMIN_USER.ID,
      viewerUserId: SEED_CONSTANTS.VIEWER_USER.ID,
      oauthClientId: SEED_CONSTANTS.OAUTH_CLIENT.ID,
      apiKeyId: SEED_CONSTANTS.API_KEY.ID,
    };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    log('[db-seed] Seeding error rolled back:', err);
    throw err;
  } finally {
    client.release();
    await pool.end();
  }
}

// Direct execution CLI entrypoint
if (process.argv[1] && process.argv[1].endsWith('seed.ts')) {
  runDatabaseSeed()
    .then((result) => {
      console.log('Seeded identifiers:', JSON.stringify(result, null, 2));
      process.exit(0);
    })
    .catch((err) => {
      console.error('Database seed execution failed:', err);
      process.exit(1);
    });
}

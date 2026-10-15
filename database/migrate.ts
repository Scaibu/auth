import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import { AUTH_CONFIG } from '../src/config/env.config';

export const MIGRATE_QUERIES = {
  CREATE_SCHEMA_MIGRATIONS_TABLE: `
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name VARCHAR(255) PRIMARY KEY,
      applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
  `,
  SELECT_APPLIED_MIGRATIONS: 'SELECT name FROM schema_migrations',
  RECORD_APPLIED_MIGRATION: 'INSERT INTO schema_migrations (name) VALUES ($1)',
  BEGIN_TRANSACTION: 'BEGIN',
  COMMIT_TRANSACTION: 'COMMIT',
  ROLLBACK_TRANSACTION: 'ROLLBACK',
} as const;

const connectionString = AUTH_CONFIG.db.url;

const pool = new pg.Pool({ connectionString });

pool.on('error', (err: any) => {
  console.warn('[db-migrate] PostgreSQL pool error handled:', err?.message || err);
});

async function connectWithRetry(maxRetries = 10, delayMs = 1500) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const client = await pool.connect();
      client.on('error', (err: any) => {
        console.warn('[db-migrate] PostgreSQL client error handled:', err?.message || err);
      });
      return client;
    } catch (err) {
      if (attempt === maxRetries) throw err;
      console.log(`[db-migrate] Waiting for database readiness (attempt ${attempt}/${maxRetries})...`);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  throw new Error('[db-migrate] Unable to connect to database after maximum retries');
}

export async function runMigrations() {
  let client: pg.PoolClient | null = null;
  try {
    client = await connectWithRetry();
    await client.query(MIGRATE_QUERIES.CREATE_SCHEMA_MIGRATIONS_TABLE);

    const { rows } = await client.query<{ name: string }>(MIGRATE_QUERIES.SELECT_APPLIED_MIGRATIONS);
    const appliedSet = new Set(rows.map((r) => r.name));

    const candidateDirs = [
      path.join(__dirname, 'migrations'),
      path.join(process.cwd(), 'database', 'migrations'),
      path.join(__dirname, '..', 'database', 'migrations'),
    ];
    const migrationsDir = candidateDirs.find((dir) => fs.existsSync(dir));
    if (!migrationsDir) {
      throw new Error(`[db-migrate] Could not locate migrations directory in candidate paths: ${candidateDirs.join(', ')}`);
    }
    const files = fs
      .readdirSync(migrationsDir)
      .filter((f) => f.endsWith('.sql') && !f.endsWith('.rollback.sql'))
      .sort();

    console.log(`[db-migrate] Found ${files.length} migration file(s) in ${migrationsDir}.`);

    for (const file of files) {
      if (appliedSet.has(file)) {
        console.log(`  - [SKIP] ${file} (already applied)`);
        continue;
      }

      console.log(`  - [APPLYING] ${file}...`);
      const filePath = path.join(migrationsDir, file);
      const sql = fs.readFileSync(filePath, 'utf8');

      for (let attempt = 1; attempt <= 3; attempt++) {
        try {
          if (!client) {
            client = await connectWithRetry();
          }
          await client.query(MIGRATE_QUERIES.BEGIN_TRANSACTION);
          await client.query(sql);
          await client.query(MIGRATE_QUERIES.RECORD_APPLIED_MIGRATION, [file]);
          await client.query(MIGRATE_QUERIES.COMMIT_TRANSACTION);
          console.log(`  - [DONE] ${file}`);
          break;
        } catch (fileErr: any) {
          if (client) {
            await client.query(MIGRATE_QUERIES.ROLLBACK_TRANSACTION).catch(() => { });
            try { client.release(); } catch { }
            client = null;
          }
          if (attempt === 3) throw fileErr;
          console.warn(`  - [RETRY] ${file} (attempt ${attempt}/3 failed: ${fileErr?.message || fileErr}). Retrying in 2s...`);
          await new Promise((r) => setTimeout(r, 2000));
        }
      }
    }

    console.log('[db-migrate] ✓ All database migrations applied successfully.');
  } catch (error) {
    if (client) {
      await client.query(MIGRATE_QUERIES.ROLLBACK_TRANSACTION).catch(() => { });
    }
    console.error('[db-migrate] ✗ Migration failed:', error);
    throw error;
  } finally {
    if (client) {
      try { client.release(); } catch { }
    }
    await pool.end().catch(() => { });
  }
}

const isDirectExecution = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isDirectExecution) {
  runMigrations().catch(() => {
    process.exit(1);
  });
}


import pg from 'pg';
import { AUTH_CONFIG } from '../src/config/env.config';

export interface DbProvisionOptions {
  superUser?: string;
  superPassword?: string;
  targetUser?: string;
  targetPassword?: string;
  targetDatabase?: string;
  host?: string;
  port?: number;
}

export async function ensureDatabaseAndRole(options?: DbProvisionOptions): Promise<{ success: boolean; message: string }> {
  const host = options?.host ?? AUTH_CONFIG.db.host;
  const port = options?.port ?? AUTH_CONFIG.db.port;
  const targetUser = options?.targetUser ?? AUTH_CONFIG.db.user;
  const targetPassword = options?.targetPassword ?? AUTH_CONFIG.db.password;
  const targetDatabase = options?.targetDatabase ?? AUTH_CONFIG.db.name;

  const superUser = options?.superUser ?? AUTH_CONFIG.db.superUser;
  const superPassword = options?.superPassword ?? AUTH_CONFIG.db.superPassword;
  const superDatabase = options?.superDatabase ?? AUTH_CONFIG.db.superDatabase;

  const superUsersToTry: Array<{ user: string; password?: string; db: string }> = [];

  if (superUser && superPassword && superDatabase) {
    superUsersToTry.push({ user: superUser, password: superPassword, db: superDatabase });
  }
  superUsersToTry.push({ user: targetUser, password: targetPassword, db: targetDatabase });

  let adminClient: pg.Client | null = null;
  let connectedUser = '';

  for (const cred of superUsersToTry) {
    try {
      const client = new pg.Client({
        host,
        port,
        user: cred.user,
        password: cred.password,
        database: cred.db,
        connectionTimeoutMillis: 3000,
      });
      await client.connect();
      adminClient = client;
      connectedUser = cred.user;
      break;
    } catch {
      continue;
    }
  }

  if (!adminClient) {
    return {
      success: false,
      message: `Unable to connect to PostgreSQL / AlloyDB instance at ${host}:${port} with any known administrative credentials.`,
    };
  }

  try {
    const roleCheck = await adminClient.query(
      'SELECT 1 FROM pg_roles WHERE rolname = $1',
      [targetUser]
    );

    if (roleCheck.rowCount === 0) {
      await adminClient.query(
        `CREATE ROLE "${targetUser}" WITH LOGIN SUPERUSER PASSWORD '${targetPassword.replace(/'/g, "''")}';`
      );
    } else {
      await adminClient.query(
        `ALTER ROLE "${targetUser}" WITH LOGIN SUPERUSER PASSWORD '${targetPassword.replace(/'/g, "''")}';`
      );
    }

    const dbCheck = await adminClient.query(
      'SELECT 1 FROM pg_database WHERE datname = $1',
      [targetDatabase]
    );

    if (dbCheck.rowCount === 0) {
      await adminClient.query(
        `CREATE DATABASE "${targetDatabase}" OWNER "${targetUser}";`
      );
    } else {
      await adminClient.query(
        `GRANT ALL PRIVILEGES ON DATABASE "${targetDatabase}" TO "${targetUser}";`
      );
    }

    return {
      success: true,
      message: `Database "${targetDatabase}" and user "${targetUser}" provisioned successfully via ${connectedUser}.`,
    };
  } catch (err: any) {
    return {
      success: false,
      message: `Provisioning failed: ${err.message || err}`,
    };
  } finally {
    await adminClient.end().catch(() => {});
  }
}

if (process.argv[1]?.endsWith('provision-db.ts')) {
  ensureDatabaseAndRole()
    .then((result) => {
      console.log(result.message);
      if (!result.success) process.exit(1);
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}

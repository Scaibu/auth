import { RealPostgresAuthAdapter } from './real-postgres-auth.adapter';

/**
 * PostgreSQL Auth Repository Adapter.
 * Canonical implementation backed by RealPostgresAuthAdapter.
 * The AlloyDBOmniAuthAdapter (in-memory mock) has been retired.
 */
export class PostgresAuthAdapter extends RealPostgresAuthAdapter {}

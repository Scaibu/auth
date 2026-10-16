import { describe, it, expect, vi } from 'vitest';
import { runDatabaseSeed, SEED_CONSTANTS } from '../../database/seeds/seed';

vi.mock('pg', () => {
  const queryMock = vi.fn().mockImplementation(() => {
    return Promise.resolve({ rows: [], rowCount: 1 });
  });

  const clientMock = {
    query: queryMock,
    release: vi.fn(),
  };

  const poolMock = {
    connect: vi.fn().mockResolvedValue(clientMock),
    on: vi.fn(),
    end: vi.fn().mockResolvedValue(undefined),
  };

  function MockPool() {
    return poolMock;
  }

  return {
    default: {
      Pool: MockPool,
    },
    Pool: MockPool,
  };
});

describe('Database Seeder (runDatabaseSeed)', () => {
  it('should execute idempotent inserts for organization, admin, viewer, oauth client, and api key', async () => {
    const result = await runDatabaseSeed({ silent: true });

    expect(result).toBeDefined();
    expect(result.organizationId).toBe(SEED_CONSTANTS.ORGANIZATION.ID);
    expect(result.adminUserId).toBe(SEED_CONSTANTS.ADMIN_USER.ID);
    expect(result.viewerUserId).toBe(SEED_CONSTANTS.VIEWER_USER.ID);
    expect(result.oauthClientId).toBe(SEED_CONSTANTS.OAUTH_CLIENT.ID);
    expect(result.apiKeyId).toBe(SEED_CONSTANTS.API_KEY.ID);
  });
});

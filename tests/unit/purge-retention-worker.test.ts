import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { PurgeRetentionWorker } from '../../src/infra/workers/purge-retention.worker';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import type { ICachePort } from '../../src/shared/ports/cache.interface';

class MockMemoryCache implements ICachePort {
  private readonly store = new Map<string, string>();

  async get(key: string): Promise<string | null> {
    return this.store.get(key) ?? null;
  }

  async set(key: string, value: string): Promise<void> {
    this.store.set(key, value);
  }

  async del(key: string): Promise<void> {
    this.store.delete(key);
  }

  async exists(key: string): Promise<boolean> {
    return this.store.has(key);
  }
}

describe('PurgeRetentionWorker (GDPR Article 17)', () => {
  let repo: AlloyDBOmniAuthAdapter;
  let cache: MockMemoryCache;

  beforeEach(() => {
    repo = new AlloyDBOmniAuthAdapter();
    cache = new MockMemoryCache();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('successfully purges expired soft-deleted entities and releases lock', async () => {
    vi.spyOn(repo, 'purgeExpiredSoftDeletes').mockResolvedValue(15);

    const worker = new PurgeRetentionWorker(repo, cache, {
      enabled: true,
      intervalMs: 1000,
    });

    const result = await worker.executePurge();

    expect(result.status).toBe('executed');
    expect(result.purgedRecords).toBe(15);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
    expect(await cache.get('auth:lock:retention_purge')).toBeNull();
  });

  it('skips execution when another instance holds the distributed lock', async () => {
    await cache.set('auth:lock:retention_purge', String(Date.now()));
    const purgeSpy = vi.spyOn(repo, 'purgeExpiredSoftDeletes');

    const worker = new PurgeRetentionWorker(repo, cache, {
      enabled: true,
    });

    const result = await worker.executePurge();

    expect(result.status).toBe('skipped_lock_busy');
    expect(result.purgedRecords).toBe(0);
    expect(purgeSpy).not.toHaveBeenCalled();
  });

  it('returns disabled status when worker is disabled by config', async () => {
    const purgeSpy = vi.spyOn(repo, 'purgeExpiredSoftDeletes');

    const worker = new PurgeRetentionWorker(repo, cache, {
      enabled: false,
    });

    const result = await worker.executePurge();

    expect(result.status).toBe('disabled');
    expect(result.purgedRecords).toBe(0);
    expect(purgeSpy).not.toHaveBeenCalled();
  });

  it('safely starts and stops unref interval timers', () => {
    const worker = new PurgeRetentionWorker(repo, cache, {
      enabled: true,
      intervalMs: 5000,
    });

    worker.start();
    worker.stop();
  });
});

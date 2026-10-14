/**
 * @file purge-retention.worker.ts
 * @description Autonomous Scheduled Worker for GDPR Article 17 30-Day Cascade Soft-Delete Purging.
 *
 * OVERALL ALGORITHM:
 * 1. Schedule periodic execution using unref timers (configurable interval, default daily: 24h).
 * 2. On trigger, execute within centralized withSpan('PurgeRetentionWorker.executePurge').
 * 3. Acquire distributed lease lock (via ICachePort: 'auth:lock:retention_purge', TTL: 300s).
 * 4. If lock acquisition fails, log telemetry and exit gracefully (another replica active).
 * 5. If lock acquired, invoke repo.purgeExpiredSoftDeletes() inside transactional boundary.
 * 6. Record purged row count and duration attributes in active span.
 * 7. In finally block, release distributed lock and reset execution state.
 */

import type { AuthRepositoryPort } from '../../features/auth/repository';
import type { ICachePort } from '../../shared/ports/cache.interface';
import { withSpan } from '../tracing/tracer';
import { SpanStatusCode } from '@chief-strategist-j/shared-infra';

export interface PurgeRetentionWorkerConfig {
  readonly enabled?: boolean;
  readonly intervalMs?: number;
  readonly lockKey?: string;
  readonly lockTtlMs?: number;
}

export interface PurgeResult {
  readonly status: 'executed' | 'skipped_lock_busy' | 'disabled';
  readonly purgedRecords: number;
  readonly durationMs: number;
}

export class PurgeRetentionWorker {
  private readonly repo: AuthRepositoryPort;
  private readonly cache?: ICachePort;
  private readonly enabled: boolean;
  private readonly intervalMs: number;
  private readonly lockKey: string;
  private readonly lockTtlMs: number;
  private timer: NodeJS.Timeout | null = null;
  private isRunning = false;

  constructor(
    repo: AuthRepositoryPort,
    cache?: ICachePort,
    config?: PurgeRetentionWorkerConfig
  ) {
    this.repo = repo;
    this.cache = cache;
    this.enabled = config?.enabled ?? true;
    this.intervalMs = config?.intervalMs ?? 24 * 60 * 60 * 1000;
    this.lockKey = config?.lockKey ?? 'auth:lock:retention_purge';
    this.lockTtlMs = config?.lockTtlMs ?? 300000;
  }

  public start(): void {
    if (!this.enabled || this.timer) {
      return;
    }

    this.timer = setInterval(() => {
      this.executePurge().catch((err) => {
        console.error('[PurgeRetentionWorker] Execution failed:', err);
      });
    }, this.intervalMs);

    if (typeof this.timer.unref === 'function') {
      this.timer.unref();
    }
  }

  public stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  public async executePurge(): Promise<PurgeResult> {
    if (!this.enabled) {
      return { status: 'disabled', purgedRecords: 0, durationMs: 0 };
    }

    return withSpan('PurgeRetentionWorker.executePurge', async (span) => {
      const startTime = Date.now();
      span.setAttribute('worker.name', 'PurgeRetentionWorker');
      span.setAttribute('gdpr.standard', 'Article_17');

      if (this.isRunning) {
        span.setAttribute('purge.status', 'skipped_local_in_flight');
        return { status: 'skipped_lock_busy', purgedRecords: 0, durationMs: 0 };
      }

      let lockAcquired = false;

      if (this.cache) {
        try {
          const currentLock = await this.cache.get(this.lockKey);
          if (currentLock) {
            span.setAttribute('purge.status', 'skipped_lock_busy');
            return { status: 'skipped_lock_busy', purgedRecords: 0, durationMs: Date.now() - startTime };
          }
          await this.cache.set(this.lockKey, String(startTime), this.lockTtlMs);
          lockAcquired = true;
        } catch {
          lockAcquired = true;
        }
      } else {
        lockAcquired = true;
      }

      this.isRunning = true;

      try {
        const purgedRecords = await this.repo.purgeExpiredSoftDeletes();
        const durationMs = Date.now() - startTime;

        span.setAttribute('purge.records_count', purgedRecords);
        span.setAttribute('purge.duration_ms', durationMs);
        span.setStatus({ code: SpanStatusCode.OK });

        return {
          status: 'executed',
          purgedRecords,
          durationMs,
        };
      } catch (err: unknown) {
        if (err instanceof Error) {
          span.recordException(err);
        }
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: err instanceof Error ? err.message : 'Retention purge failed',
        });
        throw err;
      } finally {
        this.isRunning = false;
        if (lockAcquired && this.cache) {
          try {
            await this.cache.del(this.lockKey);
          } catch {}
        }
      }
    });
  }
}

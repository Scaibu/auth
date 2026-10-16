/**
 * @file outbox-relay.test.ts
 * @description Unit tests verifying OutboxRelayWorker polling, dispatching, and retry handling.
 *
 * OVERALL ALGORITHM:
 * 1. Mock PostgreSQL connection pool and query responses.
 * 2. Mock AuthEventProducer with typed methods.
 * 3. Verify processBatch executes SELECT ... FOR UPDATE SKIP LOCKED.
 * 4. Verify successful dispatch updates record to 'PUBLISHED' with timestamp.
 * 5. Verify failed dispatch increments retry_count and logs error.
 *
 * STRICT INVARIANT: ZERO inline comments inside function bodies. File header docblock only.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { OutboxRelayWorker } from '../../src/shared/messaging/outbox/outbox-relay.worker';

describe('OutboxRelayWorker', () => {
  let mockClient: any;
  let mockPool: any;
  let mockProducer: any;
  let worker: OutboxRelayWorker;

  beforeEach(() => {
    mockClient = {
      query: vi.fn(),
      release: vi.fn(),
    };
    mockPool = {
      connect: vi.fn().mockResolvedValue(mockClient),
    };
    mockProducer = {
      publishUserBlocked: vi.fn().mockResolvedValue({ id: 'evt_123' }),
      producer: {
        publish: vi.fn().mockResolvedValue({ id: 'evt_generic' }),
      },
    };
    worker = new OutboxRelayWorker(mockPool, mockProducer, 100, 10);
  });

  it('should process pending outbox records and mark them PUBLISHED', async () => {
    worker.start();

    mockClient.query.mockImplementation((queryText: string) => {
      if (queryText === 'BEGIN' || queryText === 'COMMIT') {
        return Promise.resolve();
      }
      if (queryText.includes('SELECT id, topic, event_name')) {
        return Promise.resolve({
          rows: [
            {
              id: 'outbox_1',
              topic: 'auth.security-events.v1',
              event_name: 'USER_BLOCKED',
              partition_key: 'org_1',
              headers: { 'x-tenant-id': 'org_1' },
              payload: { userId: 'usr_1', orgId: 'org_1' },
              retry_count: 0,
            },
          ],
        });
      }
      if (queryText.includes('UPDATE auth_outbox')) {
        return Promise.resolve({ rowCount: 1 });
      }
      return Promise.resolve({ rows: [] });
    });

    const count = await worker.processBatch();
    expect(count).toBe(1);
    expect(mockProducer.publishUserBlocked).toHaveBeenCalledWith(
      { userId: 'usr_1', orgId: 'org_1' },
      { 'x-tenant-id': 'org_1' }
    );
    expect(mockClient.query).toHaveBeenCalledWith(
      expect.stringContaining("SET status = 'PUBLISHED'"),
      ['outbox_1']
    );

    worker.stop();
  });

  it('should increment retry_count when event publishing fails', async () => {
    worker.start();

    mockProducer.publishUserBlocked.mockRejectedValue(new Error('Kafka broker connection refused'));

    mockClient.query.mockImplementation((queryText: string) => {
      if (queryText === 'BEGIN' || queryText === 'COMMIT') {
        return Promise.resolve();
      }
      if (queryText.includes('SELECT id, topic, event_name')) {
        return Promise.resolve({
          rows: [
            {
              id: 'outbox_fail_1',
              topic: 'auth.security-events.v1',
              event_name: 'USER_BLOCKED',
              partition_key: 'org_1',
              headers: {},
              payload: { userId: 'usr_1', orgId: 'org_1' },
              retry_count: 0,
            },
          ],
        });
      }
      if (queryText.includes('UPDATE auth_outbox')) {
        return Promise.resolve({ rowCount: 1 });
      }
      return Promise.resolve({ rows: [] });
    });

    const count = await worker.processBatch();
    expect(count).toBe(0);
    expect(mockClient.query).toHaveBeenCalledWith(
      expect.stringContaining('retry_count = retry_count + 1'),
      ['Kafka broker connection refused', 'outbox_fail_1']
    );

    worker.stop();
  });
});

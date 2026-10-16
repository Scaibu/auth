import { describe, it, expect, beforeEach, vi } from 'vitest';
import { HoneytokenService } from '../../src/features/auth/services/honeytoken.service';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('HoneytokenService Unit Tests (ADR 0041)', () => {
  let service: HoneytokenService;
  let mockRepo: any;
  let mockRedis: any;
  let mockEventProducer: any;

  beforeEach(() => {
    mockRepo = {
      saveHoneytoken: vi.fn().mockResolvedValue(undefined),
      findHoneytokenByHash: vi.fn(),
      recordHoneytokenTrip: vi.fn().mockResolvedValue(undefined),
      listHoneytokensByOrgId: vi.fn().mockResolvedValue([]),
      revokeHoneytoken: vi.fn().mockResolvedValue(undefined),
    };

    mockRedis = {
      set: vi.fn().mockResolvedValue('OK'),
    };

    mockEventProducer = {
      emit: vi.fn().mockResolvedValue(undefined),
    };

    service = new HoneytokenService(mockRepo, mockRedis, mockEventProducer);
  });

  describe('createHoneytoken', () => {
    it('generates high-entropy canary secret with canonical prefix and stores hash', async () => {
      const res = await service.createHoneytoken({
        org_id: 'org_test_1',
        name: 'GitHub Canary Trap',
        deployed_location: 'repo:service/.env.example',
      });

      expect(res.token).toMatch(/^ht_canary_[0-9a-f]{48}$/);
      expect(res.prefix).toBe(AUTH_CONSTANTS.HONEYTOKEN.DEFAULT_PREFIX);
      expect(res.name).toBe('GitHub Canary Trap');
      expect(res.org_id).toBe('org_test_1');
      expect(res.status).toBe('ACTIVE');

      expect(mockRepo.saveHoneytoken).toHaveBeenCalledOnce();
      const savedRecord = mockRepo.saveHoneytoken.mock.calls[0][0];
      expect(savedRecord.token_hash).toBe(service.hashToken(res.token));
      expect(savedRecord.tripwire_count).toBe(0);
    });

    it('throws validation error if required fields are missing', async () => {
      await expect(service.createHoneytoken({ org_id: '', name: 'test' })).rejects.toThrow();
      await expect(service.createHoneytoken({ org_id: 'org_1', name: '  ' })).rejects.toThrow();
    });
  });

  describe('inspectAndTrip', () => {
    it('ignores non-honeytoken strings without DB queries', async () => {
      const res = await service.inspectAndTrip('valid_jwt_token_or_other_key', {
        ip: '1.2.3.4',
        userAgent: 'curl/8.0',
      });

      expect(res.isHoneytoken).toBe(false);
      expect(res.tripped).toBe(false);
      expect(mockRepo.findHoneytokenByHash).not.toHaveBeenCalled();
    });

    it('silently trips honeytoken, blacklists IP in Redis, and emits security alert', async () => {
      const canarySecret = 'ht_canary_abc123456789012345678901234567890123456789012345';
      const tokenHash = service.hashToken(canarySecret);

      mockRepo.findHoneytokenByHash.mockResolvedValue({
        id: 'ht_canary_001',
        token_hash: tokenHash,
        name: 'CI Trap',
        org_id: 'org_enterprise',
        status: 'ACTIVE',
        tripwire_count: 0,
      });

      const res = await service.inspectAndTrip(canarySecret, {
        ip: '198.51.100.42',
        userAgent: 'AttackerBot/1.0',
      });

      expect(res.isHoneytoken).toBe(true);
      expect(res.tripped).toBe(true);
      expect(res.honeytokenId).toBe('ht_canary_001');

      expect(mockRepo.recordHoneytokenTrip).toHaveBeenCalledWith(
        'ht_canary_001',
        expect.objectContaining({
          ip: '198.51.100.42',
          userAgent: 'AttackerBot/1.0',
        })
      );

      expect(mockRedis.set).toHaveBeenCalledWith(
        'denylist:ip:198.51.100.42',
        expect.stringContaining('HONEYTOKEN_TRIPWIRE'),
        'EX',
        86400
      );

      expect(mockEventProducer.emit).toHaveBeenCalledWith(
        AUTH_CONSTANTS.HONEYTOKEN.KAFKA_TOPIC_TRIPPED,
        expect.objectContaining({
          canary_id: 'ht_canary_001',
          attacker_ip: '198.51.100.42',
        })
      );
    });
  });

  describe('listHoneytokens and revokeHoneytoken', () => {
    it('lists canary records by organization', async () => {
      mockRepo.listHoneytokensByOrgId.mockResolvedValue([
        { id: 'ht_1', name: 'Trap 1', org_id: 'org_1' },
      ]);

      const list = await service.listHoneytokens('org_1');
      expect(list).toHaveLength(1);
      expect(list[0].id).toBe('ht_1');
    });

    it('revokes canary record', async () => {
      await service.revokeHoneytoken('ht_1', 'org_1');
      expect(mockRepo.revokeHoneytoken).toHaveBeenCalledWith('ht_1', 'org_1');
    });
  });
});

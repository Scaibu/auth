import { describe, it, expect, vi } from 'vitest';
import { RealGeoIpAdapter } from '../../src/infra/adapters/geo/real-geo-ip.adapter';

describe('RealGeoIpAdapter Unit Tests', () => {
  it('resolves private and loopback subnets immediately without external network calls', async () => {
    const adapter = new RealGeoIpAdapter({
      provider: 'http',
      httpEndpoint: 'https://ipwho.is',
      timeoutMs: 1500,
    });

    const loopback = await adapter.lookup('127.0.0.1');
    expect(loopback.ip).toBe('127.0.0.1');
    expect(loopback.isDatacenter).toBe(false);
    expect(loopback.asn).toBe('AS_PRIVATE_LAN');

    const privateLan = await adapter.lookup('192.168.1.50');
    expect(privateLan.isDatacenter).toBe(false);
    expect(privateLan.asn).toBe('AS_PRIVATE_LAN');
  });

  it('fetches and caches public IP telemetry from HTTP provider with datacenter ASN inspection', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        ip: '198.51.100.25',
        latitude: 37.751,
        longitude: -122.42,
        connection: { asn: 16509 }, // AWS Datacenter ASN
        security: { is_vpn: false, is_proxy: false },
      }),
    });
    vi.stubGlobal('fetch', mockFetch);

    const adapter = new RealGeoIpAdapter({
      provider: 'http',
      httpEndpoint: 'https://ipwho.is',
      timeoutMs: 1500,
    });

    const result = await adapter.lookup('198.51.100.25');
    expect(result.ip).toBe('198.51.100.25');
    expect(result.asn).toBe('AS16509');
    expect(result.isDatacenter).toBe(true);
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // Subsequent lookup for same IP must hit internal LRU cache
    const cachedResult = await adapter.lookup('198.51.100.25');
    expect(cachedResult.asn).toBe('AS16509');
    expect(mockFetch).toHaveBeenCalledTimes(1);

    vi.unstubAllGlobals();
  });

  it('fails open to default safe telemetry when network fetch times out or errors', async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error('Network timeout'));
    vi.stubGlobal('fetch', mockFetch);

    const adapter = new RealGeoIpAdapter({
      provider: 'http',
      httpEndpoint: 'https://ipwho.is',
      timeoutMs: 100,
    });

    const result = await adapter.lookup('8.8.8.8');
    expect(result.ip).toBe('8.8.8.8');
    expect(result.isDatacenter).toBe(false);

    vi.unstubAllGlobals();
  });
});

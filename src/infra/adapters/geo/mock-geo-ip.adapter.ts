import type { GeoIpPort } from '../../../features/auth/ports/geo-ip.port';
import type { GeoLocationTelemetry } from '../../../features/auth/types';

export class MockGeoIpAdapter implements GeoIpPort {
  private readonly overrides: Map<string, GeoLocationTelemetry>;

  constructor(customOverrides?: ReadonlyMap<string, GeoLocationTelemetry>) {
    this.overrides = customOverrides ? new Map(customOverrides) : new Map();
  }

  setOverride(ip: string, telemetry: GeoLocationTelemetry): void {
    this.overrides.set(ip, telemetry);
  }

  async lookup(ip: string): Promise<GeoLocationTelemetry> {
    if (this.overrides.has(ip)) {
      return this.overrides.get(ip)!;
    }

    if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip === '127.0.0.1' || ip === '::1') {
      return {
        ip,
        latitude: 37.7749,
        longitude: -122.4194,
        asn: 'AS13335',
        isDatacenter: false,
      };
    }

    if (ip.startsWith('198.51.100.') || ip.startsWith('203.0.113.')) {
      return {
        ip,
        latitude: 40.7128,
        longitude: -74.0060,
        asn: 'AS16509',
        isDatacenter: true,
      };
    }

    return {
      ip,
      latitude: 37.7749,
      longitude: -122.4194,
      asn: 'AS7922',
      isDatacenter: false,
    };
  }
}

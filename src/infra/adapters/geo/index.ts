import type { GeoIpPort } from '../../../features/auth/ports/geo-ip.port';
import type { GeoIpConfig } from '../../../config/geoip.config';
import { MockGeoIpAdapter } from './mock-geo-ip.adapter';
import { RealGeoIpAdapter } from './real-geo-ip.adapter';

export function createGeoIpAdapter(config: GeoIpConfig): GeoIpPort {
  if (config.provider === 'mock') {
    return new MockGeoIpAdapter();
  }
  return new RealGeoIpAdapter(config);
}

export { MockGeoIpAdapter, RealGeoIpAdapter };

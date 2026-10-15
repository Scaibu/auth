import type { GeoLocationTelemetry } from '../types';

export interface GeoIpPort {
  lookup(ip: string): Promise<GeoLocationTelemetry>;
}

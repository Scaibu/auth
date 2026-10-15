/**
 * @file geoip.config.ts
 * @description Declarative GeoIP Resolver Configuration for adaptive risk-based authentication.
 */

export interface GeoIpConfig {
  readonly provider: 'mock' | 'http' | 'local';
  readonly httpEndpoint?: string;
  readonly dbPath?: string;
  readonly timeoutMs: number;
}

export const DEFAULT_GEOIP_CONFIG: GeoIpConfig = Object.freeze({
  provider: 'mock',
  httpEndpoint: 'https://ipwho.is',
  timeoutMs: 1500,
});

export function loadGeoIpConfig(): GeoIpConfig {
  const provider = (process.env.AUTH_GEOIP_PROVIDER || DEFAULT_GEOIP_CONFIG.provider) as 'mock' | 'http' | 'local';
  return Object.freeze({
    provider,
    httpEndpoint: process.env.AUTH_GEOIP_HTTP_ENDPOINT || DEFAULT_GEOIP_CONFIG.httpEndpoint,
    dbPath: process.env.AUTH_GEOIP_DB_PATH,
    timeoutMs: parseInt(process.env.AUTH_GEOIP_TIMEOUT_MS || String(DEFAULT_GEOIP_CONFIG.timeoutMs), 10),
  });
}

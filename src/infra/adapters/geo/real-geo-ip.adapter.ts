import { withSpan } from '../../tracing/tracer';
import { SpanKind } from '@chief-strategist-j/shared-infra/tracing';
import type { GeoIpPort } from '../../../features/auth/ports/geo-ip.port';
import type { GeoLocationTelemetry } from '../../../features/auth/types';
import type { GeoIpConfig } from '../../../config/geoip.config';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';

const CLOUD_DATACENTER_ASNS = new Set<string>(AUTH_CONSTANTS.GEO.DATACENTER_ASNS);

export class RealGeoIpAdapter implements GeoIpPort {
  private readonly config: GeoIpConfig;
  private readonly cache = new Map<string, GeoLocationTelemetry>();

  constructor(config: GeoIpConfig) {
    this.config = config;
  }

  private isPrivateOrLoopback(ip: string): boolean {
    if (
      ip === AUTH_CONSTANTS.GEO.LOOPBACK_IPV4 ||
      ip === AUTH_CONSTANTS.GEO.LOOPBACK_IPV6 ||
      ip === AUTH_CONSTANTS.GEO.LOCALHOST ||
      ip.startsWith(AUTH_CONSTANTS.GEO.PRIVATE_PREFIX_10) ||
      ip.startsWith(AUTH_CONSTANTS.GEO.PRIVATE_PREFIX_192)
    ) {
      return true;
    }

    return AUTH_CONSTANTS.GEO.PRIVATE_PREFIXES_172.some((prefix) => ip.startsWith(prefix));
  }

  async lookup(ip: string): Promise<GeoLocationTelemetry> {
    return withSpan(AUTH_CONSTANTS.GEO.SPAN_GEO_LOOKUP, async (span) => {
      span.setAttribute(AUTH_CONSTANTS.GEO.ATTR_NET_PEER_IP, ip);

      if (this.cache.has(ip)) {
        const cached = this.cache.get(ip)!;
        span.setAttribute(AUTH_CONSTANTS.GEO.ATTR_GEO_CACHED, true);
        span.setAttribute(AUTH_CONSTANTS.GEO.ATTR_GEO_IS_DATACENTER, cached.isDatacenter ?? false);
        return cached;
      }

      if (this.isPrivateOrLoopback(ip)) {
        const telemetry: GeoLocationTelemetry = {
          ip,
          latitude: AUTH_CONSTANTS.GEO.DEFAULT_LATITUDE,
          longitude: AUTH_CONSTANTS.GEO.DEFAULT_LONGITUDE,
          asn: AUTH_CONSTANTS.GEO.ASN_PRIVATE_LAN,
          isDatacenter: false,
        };
        span.setAttribute(AUTH_CONSTANTS.GEO.ATTR_GEO_IS_PRIVATE, true);
        span.setAttribute(AUTH_CONSTANTS.GEO.ATTR_GEO_IS_DATACENTER, false);
        this.cache.set(ip, telemetry);
        return telemetry;
      }

      if (this.config.provider === 'http' && this.config.httpEndpoint) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), this.config.timeoutMs);
          const response = await fetch(`${this.config.httpEndpoint}/${encodeURIComponent(ip)}`, {
            signal: controller.signal,
          });
          clearTimeout(timeoutId);

          if (response.ok) {
            const data: any = await response.json();
            const asn = data.connection?.asn
              ? `${AUTH_CONSTANTS.GEO.ASN_PREFIX}${data.connection.asn}`
              : data.asn;
            const isDatacenter =
              Boolean(data.security?.is_vpn) ||
              Boolean(data.security?.is_proxy) ||
              Boolean(data.security?.is_tor) ||
              (asn ? CLOUD_DATACENTER_ASNS.has(asn) : false);

            const telemetry: GeoLocationTelemetry = {
              ip,
              latitude: typeof data.latitude === 'number' ? data.latitude : undefined,
              longitude: typeof data.longitude === 'number' ? data.longitude : undefined,
              asn,
              isDatacenter,
            };

            span.setAttribute(AUTH_CONSTANTS.GEO.ATTR_GEO_ASN, asn || AUTH_CONSTANTS.GEO.UNKNOWN_VAL);
            span.setAttribute(AUTH_CONSTANTS.GEO.ATTR_GEO_IS_DATACENTER, isDatacenter);
            this.cache.set(ip, telemetry);
            return telemetry;
          }
        } catch (err: any) {
          span.recordException(err);
        }
      }

      const defaultTelemetry: GeoLocationTelemetry = {
        ip,
        latitude: AUTH_CONSTANTS.GEO.DEFAULT_LATITUDE,
        longitude: AUTH_CONSTANTS.GEO.DEFAULT_LONGITUDE,
        asn: AUTH_CONSTANTS.GEO.ASN_DEFAULT_RESIDENTIAL,
        isDatacenter: false,
      };
      this.cache.set(ip, defaultTelemetry);
      return defaultTelemetry;
    }, { kind: SpanKind.CLIENT });
  }
}

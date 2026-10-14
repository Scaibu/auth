import { AUTH_CONSTANTS } from '../constants/auth.constants';

export interface ClientContext {
  readonly ipAddress: string;
  readonly userAgent: string;
}

export function extractClientContext(headers?: Record<string, string>): ClientContext {
  const ipAddress =
    headers?.[AUTH_CONSTANTS.HEADERS.FORWARDED_FOR] ??
    headers?.[AUTH_CONSTANTS.HEADERS.FORWARDED_FOR.toUpperCase()] ??
    AUTH_CONSTANTS.DEFAULTS.IP_ADDRESS;

  const userAgent =
    headers?.[AUTH_CONSTANTS.HEADERS.USER_AGENT] ??
    headers?.[AUTH_CONSTANTS.HEADERS.USER_AGENT.toLowerCase()] ??
    AUTH_CONSTANTS.DEFAULTS.USER_AGENT;

  return { ipAddress, userAgent };
}

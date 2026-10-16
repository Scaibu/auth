/**
 * @file cidr.util.ts
 * @description Pure deterministic IPv4 and IPv6 CIDR subnet matching utility.
 *
 * OVERALL ALGORITHM:
 * 1. parseIpv4ToUint32: converts a dotted-decimal IPv4 string to a 32-bit unsigned integer for bitwise comparison.
 * 2. parseIpv6ToBuffer: parses a full or compressed IPv6 string (including IPv4-mapped forms) into a 16-byte Uint8Array.
 * 3. isIpv4: detects dotted-decimal addresses; isIpv6: detects colon-notation addresses.
 * 4. expandIpv4MappedIpv6: strips the ::ffff: prefix and delegates to IPv4 matching.
 * 5. matchCidrIpv4: masks both the candidate IP and the CIDR base address to the prefix length using a uint32 bitmask,
 *    then compares with strict equality.
 * 6. matchCidrIpv6: aligns to byte and bit boundaries for the prefix length, masks each byte, and compares all 16 bytes.
 * 7. checkCidrAllowlist: iterates the allowlist; an empty allowlist always returns true (unrestricted key); the first
 *    matching CIDR block short-circuits and returns true; exhausted iteration returns false.
 */

const IPV4_PATTERN = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV4_MAPPED_PREFIX = '::ffff:';
const CIDR_SEPARATOR = '/';
const IPV6_GROUP_COUNT = 8;
const IPV6_BYTES = 16;
const BITS_PER_BYTE = 8;
const UINT32_MAX_BITS = 32;
const UINT32_MASK_ALL = 0xffffffff;

function parseIpv4ToUint32(ip: string): number {
  const octets = ip.split('.').map(Number);
  return ((octets[0]! << 24) | (octets[1]! << 16) | (octets[2]! << 8) | octets[3]!) >>> 0;
}

function expandIpv6Groups(ip: string): number[] {
  const halves = ip.split('::');
  if (halves.length === 2) {
    const left = halves[0] ? halves[0].split(':').map((h) => parseInt(h, 16)) : [];
    const right = halves[1] ? halves[1].split(':').map((h) => parseInt(h, 16)) : [];
    const missing = IPV6_GROUP_COUNT - left.length - right.length;
    return [...left, ...Array(missing).fill(0), ...right];
  }
  return ip.split(':').map((h) => parseInt(h, 16));
}

function parseIpv6ToBuffer(ip: string): Uint8Array {
  const cleanIp = ip.toLowerCase().startsWith(IPV4_MAPPED_PREFIX)
    ? '::ffff:' + ip.slice(IPV4_MAPPED_PREFIX.length)
    : ip.toLowerCase();

  const groups = expandIpv6Groups(cleanIp);
  const buf = new Uint8Array(IPV6_BYTES);
  for (let i = 0; i < IPV6_GROUP_COUNT; i++) {
    buf[i * 2] = (groups[i]! >> BITS_PER_BYTE) & 0xff;
    buf[i * 2 + 1] = groups[i]! & 0xff;
  }
  return buf;
}

function isIpv4(ip: string): boolean {
  return IPV4_PATTERN.test(ip);
}

function matchCidrIpv4(ip: string, cidrBase: string, prefixLen: number): boolean {
  const mask = prefixLen === 0 ? 0 : (UINT32_MASK_ALL << (UINT32_MAX_BITS - prefixLen)) >>> 0;
  const ipInt = parseIpv4ToUint32(ip);
  const baseInt = parseIpv4ToUint32(cidrBase);
  return (ipInt & mask) === (baseInt & mask);
}

function matchCidrIpv6(ip: string, cidrBase: string, prefixLen: number): boolean {
  const ipBuf = parseIpv6ToBuffer(ip);
  const baseBuf = parseIpv6ToBuffer(cidrBase);
  const fullBytes = Math.floor(prefixLen / BITS_PER_BYTE);
  const remainingBits = prefixLen % BITS_PER_BYTE;

  for (let i = 0; i < fullBytes; i++) {
    if (ipBuf[i] !== baseBuf[i]) return false;
  }

  if (remainingBits > 0 && fullBytes < IPV6_BYTES) {
    const mask = (0xff << (BITS_PER_BYTE - remainingBits)) & 0xff;
    if ((ipBuf[fullBytes]! & mask) !== (baseBuf[fullBytes]! & mask)) return false;
  }

  return true;
}

function matchSingleCidr(ip: string, cidr: string): boolean {
  const separatorIdx = cidr.lastIndexOf(CIDR_SEPARATOR);
  if (separatorIdx === -1) return false;

  const base = cidr.slice(0, separatorIdx);
  const prefixLen = parseInt(cidr.slice(separatorIdx + 1), 10);
  if (isNaN(prefixLen)) return false;

  const normalizedIp = ip.toLowerCase().startsWith(IPV4_MAPPED_PREFIX) ? ip.slice(IPV4_MAPPED_PREFIX.length) : ip;

  if (isIpv4(normalizedIp) && isIpv4(base)) {
    return matchCidrIpv4(normalizedIp, base, prefixLen);
  }

  if (!isIpv4(normalizedIp) && !isIpv4(base)) {
    return matchCidrIpv6(normalizedIp, base, prefixLen);
  }

  return false;
}

export function checkCidrAllowlist(clientIp: string, allowlist: readonly string[]): boolean {
  if (allowlist.length === 0) return true;
  for (const cidr of allowlist) {
    if (matchSingleCidr(clientIp, cidr)) return true;
  }
  return false;
}

export function extractSubnetPrefix(ip: string): string {
  const normalized = ip.toLowerCase().startsWith(IPV4_MAPPED_PREFIX) ? ip.slice(IPV4_MAPPED_PREFIX.length) : ip;
  if (isIpv4(normalized)) {
    const octets = normalized.split('.');
    return `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
  }
  const groups = expandIpv6Groups(normalized);
  const p1 = (groups[0] ?? 0).toString(16);
  const p2 = (groups[1] ?? 0).toString(16);
  const p3 = (groups[2] ?? 0).toString(16);
  return `${p1}:${p2}:${p3}::/48`;
}

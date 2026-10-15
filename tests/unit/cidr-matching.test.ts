import { describe, it, expect } from 'vitest';
import { checkCidrAllowlist } from '../../src/shared/utils/cidr.util';

describe('CIDR Subnet Matching Utility (ADR 0027)', () => {
  it('allows all client IPs when allowlist is empty', () => {
    expect(checkCidrAllowlist('192.168.1.50', [])).toBe(true);
    expect(checkCidrAllowlist('10.0.0.1', [])).toBe(true);
    expect(checkCidrAllowlist('2001:db8::1', [])).toBe(true);
  });

  it('correctly matches IPv4 addresses against IPv4 CIDR blocks', () => {
    const allowlist = ['10.0.0.0/8', '192.168.1.0/24', '172.16.50.4/32'];

    expect(checkCidrAllowlist('10.1.2.3', allowlist)).toBe(true);
    expect(checkCidrAllowlist('10.255.255.254', allowlist)).toBe(true);
    expect(checkCidrAllowlist('192.168.1.100', allowlist)).toBe(true);
    expect(checkCidrAllowlist('172.16.50.4', allowlist)).toBe(true);

    expect(checkCidrAllowlist('192.168.2.1', allowlist)).toBe(false);
    expect(checkCidrAllowlist('172.16.50.5', allowlist)).toBe(false);
    expect(checkCidrAllowlist('8.8.8.8', allowlist)).toBe(false);
  });

  it('correctly matches /0 prefix as global allow', () => {
    expect(checkCidrAllowlist('123.45.67.89', ['0.0.0.0/0'])).toBe(true);
  });

  it('correctly handles IPv4-mapped IPv6 addresses', () => {
    const allowlist = ['10.0.0.0/8'];
    expect(checkCidrAllowlist('::ffff:10.5.5.5', allowlist)).toBe(true);
    expect(checkCidrAllowlist('::ffff:192.168.1.1', allowlist)).toBe(false);
  });

  it('correctly matches native IPv6 CIDR blocks', () => {
    const allowlist = ['2001:db8::/32', 'fe80::/10'];

    expect(checkCidrAllowlist('2001:db8:85a3::8a2e:370:7334', allowlist)).toBe(true);
    expect(checkCidrAllowlist('fe80::1', allowlist)).toBe(true);

    expect(checkCidrAllowlist('2001:db9::1', allowlist)).toBe(false);
    expect(checkCidrAllowlist('2607:f8b0:4005:805::200e', allowlist)).toBe(false);
  });

  it('rejects malformed or mismatched IP and CIDR formats safely', () => {
    expect(checkCidrAllowlist('not-an-ip', ['10.0.0.0/8'])).toBe(false);
    expect(checkCidrAllowlist('10.0.0.1', ['malformed-cidr'])).toBe(false);
    expect(checkCidrAllowlist('10.0.0.1', ['10.0.0.0/invalid'])).toBe(false);
    expect(checkCidrAllowlist('2001:db8::1', ['10.0.0.0/8'])).toBe(false);
    expect(checkCidrAllowlist('10.0.0.1', ['2001:db8::/32'])).toBe(false);
  });
});
